package ossl

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// Conn is used for writing to and reading from a libssl [SSL] connection.
type Conn struct {
	// ssl needs to be cleaned up on connection close
	ssl          *SSL
	sslCtxCloser io.Closer
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// closed tracks conn closure state
	closed   atomic.Bool
	closeErr error
	// activeCall indicates whether Close has been call in the low bit.
	// the rest of the bits are the number of goroutines in Conn.Write.
	activeCall atomic.Int32

	// deadlines
	readTimer  atomic.Pointer[deadlineTimer]
	writeTimer atomic.Pointer[deadlineTimer]

	// read / write mutexes
	in  sync.Mutex
	out sync.Mutex

	// logger
	logger *log.Logger

	// net
	localAddr  net.Addr
	remoteAddr net.Addr

	// enableTrace
	enableTrace bool
}

func (c *Conn) trace(msg string) {
	if !c.enableTrace {
		return
	}
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-5s",
		"[SSLConn]",
		msg,
		fmt.Sprintf("local=%+v", c.localAddr),
		fmt.Sprintf("remote=%+v", c.remoteAddr),
		fmt.Sprintf("conn=%+v", c.ssl.sockfd),
	)
}

type deadlineTimer struct {
	timer    *time.Timer
	deadline time.Time
}

// checkDeadline returns a context that expires when the deadline is reached
func (c *Conn) deadlineContext(deadline *atomic.Pointer[deadlineTimer]) (context.Context,
	context.CancelFunc) {
	d := deadline.Load()
	if d == nil || d.deadline.IsZero() {
		return context.Background(), func() {}
	}

	// If deadline already passed, return immediately expiring context
	if d.deadline.Before(time.Now()) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}

	return context.WithDeadline(context.Background(), d.deadline)
}

type opResult struct {
	n   int
	err error
}

// opWithDeadline will run the Read, Write, or Close operation with a deadline.
func (c *Conn) opWithDeadline(b []byte, timer *atomic.Pointer[deadlineTimer],
	op func([]byte) (int, error)) (int, error) {
	c.trace("Deadline begin")
	defer c.trace("Deadline end")
	tStart := time.Now()
	ctx, cancel := c.deadlineContext(timer)
	defer cancel()
	resultCh := make(chan opResult)
	go func() {
		n, err := op(b)
		resultCh <- opResult{n, err}
	}()
	select {
	case <-ctx.Done():
		c.trace(fmt.Sprintf("Deadline reached after %+v", time.Since(tStart)))
		return 0, os.ErrDeadlineExceeded
	case result := <-resultCh:
		c.trace("Deadline <-resultCh")
		return result.n, result.err
	}
}

// NewConn wraps a new [SSL] connection to the host with deadlines, tracing, and concurrency
// safety.
func NewConn(ssl *SSL, ctxCloser io.Closer, config *Config) (*Conn, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	c := &Conn{
		ssl:          ssl,
		sslCtxCloser: ctxCloser,
		localAddr:    ssl.LocalAddr(),
		remoteAddr:   ssl.RemoteAddr(),
		enableTrace:  config.ConnTraceEnabled,
	}
	if c.enableTrace {
		c.logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile|log.Lmicroseconds)
	}
	c.trace("New conn")
	return c, nil
}

// Read will read bytes into the buffer from the [SSL] connection, wrapped in an optional deadline.
func (c *Conn) Read(b []byte) (int, error) {
	c.trace("Read begin")
	defer c.trace("Read end")
	c.in.Lock()
	defer c.in.Unlock()
	if len(b) == 0 {
		return 0, nil
	}

	n, err := c.opWithDeadline(b, &c.readTimer, c.ssl.Read)
	if err != nil {
		sslErr, ok := err.(*libssl.SSLError)
		if ok && sslErr.Code == libssl.SSL_ERROR_ZERO_RETURN {
			c.trace("Read ZERO return")
		}
		return 0, newConnError("read", c.remoteAddr, err)
	}
	return n, nil
}

// Write will write bytes from the buffer to the [SSL] connection, wrapped in an optional deadline.
func (c *Conn) Write(b []byte) (int, error) {
	c.trace("Write begin")
	defer c.trace("Write end")
	// interlock with Close below
	for {
		c.trace("Write waiting...")
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)
	c.trace("Write grabbed lock")
	c.out.Lock()
	defer c.out.Unlock()

	if c.closeNotifySent {
		// we're done writing
		return 0, ErrShutdown
	}

	n, err := c.opWithDeadline(b, &c.writeTimer, c.ssl.Write)
	if err != nil {
		return n, newConnError("write", c.remoteAddr, err)
	}
	return n, nil
}

// Close will attempt to cleanly shutdown the [SSL] connection and free [SSL] resources.
func (c *Conn) Close() error {
	c.trace("Close begin")
	defer c.trace("Close end")
	var x int32
	for {
		c.trace("Close waiting...")
		x = c.activeCall.Load()
		if x&1 != 0 {
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}
	c.trace("Close grabbed lock")
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		c.trace("CloseFD")
		defer func() {
			// Wait for Read to end before we free-up the SSL objects
			c.in.Lock()
			defer c.in.Unlock()
			c.ssl.Close()
			c.sslCtxCloser.Close()
		}()
		return c.ssl.CloseFD()
	}
	return c.closeNotify()
}

// closeNotify closes the Write side of the connection by sending an close notify shutdown alert
// message to the peer.
func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()
	c.trace("Close-notify begin")
	defer c.trace("Close-notify end")
	if !c.closeNotifySent {
		// Set a Write Deadline to prevent possibly blocking forever.
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, c.closeErr = c.opWithDeadline(nil, &c.writeTimer, func(b []byte) (int, error) {
			c.trace("Close-notify shutdown")
			return 0, c.ssl.Shutdown()
		})
		defer func() {
			// Wait for Read to end before we free-up the SSL objects
			c.in.Lock()
			defer c.in.Unlock()
			c.ssl.Close()
			c.sslCtxCloser.Close()
		}()
		c.closeNotifySent = true
		c.closed.Store(true)
		// Any subsequent writes will fail.
		c.SetWriteDeadline(time.Now())
	}
	return c.closeErr
}

// LocalAddr returns the local network address, if known.
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote network address, if known.
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadlines of the [SSL] connection.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future [SSL.Read] calls
// and any currently-blocked [SSL.Read] call.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.trace("New rdeadline")
	c.readTimer.Store(&deadlineTimer{
		deadline: t,
		timer:    time.NewTimer(time.Until(t)),
	})
	return nil
}

// SetWriteDeadline sets the deadline for future [SSL.Write] calls
// and any currently-blocked [SSL.Write] call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.trace("New wdeadline")
	c.writeTimer.Store(&deadlineTimer{
		deadline: t,
		timer:    time.NewTimer(time.Until(t)),
	})
	return nil
}
