package fipstls

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// Conn is used for writing to and reading from an [SSL] connection. It wraps the connection with
// deadlines, state-tracking, debug tracing, and concurrency and memory safety.
type Conn struct {
	// ssl needs to be cleaned up on connection close
	ssl *SSL
	ctx io.Closer
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// closed tracks conn closure state
	closed   atomic.Bool
	closeErr error

	// deadlines
	readDeadline  time.Time
	writeDeadline time.Time

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
		"%s %-40s %-20s %-20s %-5s",
		"[SSLConn]",
		msg,
		fmt.Sprintf("local=%+v", c.ssl.LocalAddr()),
		fmt.Sprintf("remote=%+v", c.ssl.LocalAddr()),
		fmt.Sprintf("conn=%+v", c.ssl.FD()),
	)
}

var (
	opRead      = "read"
	opWrite     = "write"
	opClose     = "close"
	opHandshake = "handshake"
)

type opFunc func([]byte) (int, error)

// NewConn wraps a new [SSL] connection to the host with deadlines, state-tracking, debug tracing,
// and concurrency and memory safety. It will free [SSL] resources on connection closure, and
// optionally [SSLContext] resources if an ephemeral context was provided.
func NewConn(ctx *SSLContext, bio *BIO, deadline time.Time, trace bool) (*Conn, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	ssl, err := NewSSL(ctx, bio)
	if err != nil {
		defer ssl.Close()
		return nil, err
	}
	c := &Conn{
		ssl:         ssl,
		ctx:         ctx,
		localAddr:   ssl.LocalAddr(),
		remoteAddr:  ssl.RemoteAddr(),
		enableTrace: trace,
	}
	if c.enableTrace {
		c.logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile|log.Lmicroseconds)
	}
	// Dialer deadline
	if _, err := c.doIO(nil, opHandshake); err != nil {
		return nil, err
	}
	c.trace("New conn")
	return c, nil
}

// Read will read bytes into the buffer from the [SSL] connection, wrapped in an optional deadline.
func (c *Conn) Read(b []byte) (int, error) {
	c.trace("Read begin")
	defer c.trace("Read end")
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	return c.doIO(b, opRead)
}

// Write will write bytes from the buffer to the [SSL] connection, wrapped in an optional deadline.
func (c *Conn) Write(b []byte) (int, error) {
	c.trace("Write begin")
	defer c.trace("Write end")
	if c.closeNotifySent {
		// we're done writing
		return 0, ErrShutdown
	}

	return c.doIO(b, opWrite)
}

// Close will attempt to cleanly shutdown the [SSL] connection and free [SSL] and optionally
// [SSLContext] resources if a non-empty context was provided.
func (c *Conn) Close() error {
	c.trace("Close begin")
	defer c.trace("Close end")
	return c.closeNotify()
}

// closeNotify closes the Write side of the connection by sending a close notify shutdown alert
// message to the peer.
func (c *Conn) closeNotify() error {
	c.trace("Close-notify begin")
	defer c.trace("Close-notify end")
	if !c.closeNotifySent {
		// Set a Write Deadline to prevent possibly blocking forever.
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, c.closeErr = c.doIO(nil, opClose)
		defer func() {
			c.ssl.Close()
			c.ctx.Close()
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
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the deadline for future [SSL.Write] calls
// and any currently-blocked [SSL.Write] call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.trace("New wdeadline")
	c.writeDeadline = t
	return nil
}

func (c *Conn) doIO(b []byte, kind string) (int, error) {
	c.trace(fmt.Sprintf("%v doIO begin", kind))
	defer c.trace(fmt.Sprintf("%v doIO end", kind))

	d := time.Time{}
	var op opFunc
	switch kind {
	case opRead:
		d = c.readDeadline
		op = c.ssl.Read
	case opWrite:
		d = c.writeDeadline
		op = c.ssl.Write
	case opHandshake:
		op = func([]byte) (int, error) { return 0, c.ssl.Connect() }
	case opClose:
		d = c.writeDeadline
		op = func([]byte) (int, error) { return 0, c.ssl.Shutdown() }
	}

	for {
		if !d.IsZero() {
			timeout := time.Until(d)
			if timeout <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
		}

		result, err := op(b)
		if err == nil {
			return result, nil
		}

		// Check if it's an SSL error
		if err, ok := err.(*libssl.SSLError); ok {
			switch err.Code {
			case libssl.SSL_ERROR_WANT_READ, libssl.SSL_ERROR_WANT_WRITE:
				c.trace(fmt.Sprintf("%v doIO want read / write", kind))
				continue
			case libssl.SSL_ERROR_ZERO_RETURN:
				c.trace(fmt.Sprintf("%v doIO return zero", kind))
				return 0, io.EOF
			default:
				return 0, newConnError(kind, c.remoteAddr, err)
			}
		}
	}
}
