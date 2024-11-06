package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

// SSLConn is used for writing to and reading from a libssl [SSL] connection.
type SSLConn struct {
	// ssl needs to be cleaned up on connection close
	ssl *SSL
	// serverName contains the server name indicated by the client, if any.
	serverName string
	// timeout
	timeout time.Duration
	// Handshake state
	handshakeMutex      sync.Mutex
	handshakeErr        error
	isHandshakeComplete atomic.Bool
	handshakes          int // count for multiple handshakes (renegotiation)
	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent     bool
	closeNotifyReceived atomic.Bool
	connActive          atomic.Bool
	connError           atomic.Value // stores error if conn died

	// bytesSent counts the bytes of application data sent.
	bytesSent int64

	// closed tracks conn closure state
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error

	// activeCall indicates whether Close has been call in the low bit.
	// the rest of the bits are the number of goroutines in Conn.Write.
	activeCall atomic.Int32

	// deadlines
	readDeadline  time.Time
	writeDeadline time.Time

	// read / write mutexes
	in  sync.Mutex
	out sync.Mutex

	// logger
	logger *log.Logger

	// net
	local  net.Addr
	remote string
}

// NewConn creates a new SSL connection to the host.
func NewConn(ctx *SSLContext, address string, config *Config) (*SSLConn, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	ssl, err := dial(ctx, address, config)
	if err != nil {
		return nil, err
	}
	c := &SSLConn{
		ssl:        ssl,
		serverName: address,
		remote:     address,
		timeout:    config.Timeout,
		logger:     log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile|log.Lmicroseconds),
	}
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"New conn",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	c.connActive.Store(true)
	if err := c.handshakeContext(context.Background()); err != nil {
		return nil, err
	}
	return c, nil
}

// handshakeContext is borrowed from [tls.Conn]
func (c *SSLConn) handshakeContext(ctx context.Context) (ret error) {
	// Fast path - avoid mutex if handshake is done
	if c.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Setup interrupt handler for context cancellation
	if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				_ = c.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	// Check handshake state
	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	// Do SSL handshake
	err := c.connect()
	if err != nil {
		c.handshakeErr = err
		return err
	}

	c.handshakes++
	c.isHandshakeComplete.Store(true)
	return c.handshakeErr
}

func (c *SSLConn) connect() error {
	libssl.SSLClearError()
	return libssl.SSLConnect(c.ssl.ssl)
}

func dial(ctx *SSLContext, address string, config *Config) (*SSL, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	libssl.SSLClearError()
	ssl, err := NewSSL(ctx, config)
	if err != nil {
		return nil, err
	}
	// CONNECT
	if err := libssl.SSLSetConnectState(ssl.ssl); err != nil {
		return nil, err
	}
	// Set the SNI hostname
	if err := libssl.SSLSetTLSExtHostName(ssl.ssl, host); err != nil {
		return nil, err
	}
	// Set the hostname for certificate verification
	if err := libssl.SSLSet1Host(ssl.ssl, host); err != nil {
		return nil, err
	}

	bio, err := libssl.CreateBioSocket(host, port, syscall.AF_INET, 0)
	if err != nil {
		return nil, err
	}
	if err := libssl.SSLSetBio(ssl.ssl, bio, bio); err != nil {
		return nil, err
	}
	return ssl, err
}

func (c *SSLConn) Read(b []byte) (int, error) {
	return c.read(b)
}

// Read will read into bytes from the SSL connection.
func (c *SSLConn) read(b []byte) (int, error) {
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Read begin",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	defer c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Read end",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := c.handshakeContext(context.Background()); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	c.in.Lock()

	// Check shutdown state before read
	if c.isCloseNotifyReceived() {
		c.in.Unlock()
		return 0, io.EOF
	}

	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		fmt.Sprintf("Read SSL_pending %+v bytes", libssl.SSLPending(c.ssl.ssl)),
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	libssl.SSLClearError()
	r, n, err := libssl.SSLReadEx(c.ssl.ssl, int64(len(b)))
	c.in.Unlock()
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		fmt.Sprintf("Read %+v bytes", n),
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	if err != nil {
		return n, NewSSLConnError("read", c.remote, err)
	}
	if c.isCloseNotifyReceived() {
		return n, io.EOF
	}
	copy(b, r[:n])
	return n, nil
}

var (
	errShutdown = errors.New("tls: protocol is shutdown")
)

func (c *SSLConn) Write(b []byte) (int, error) {
	return c.write(b)
}

// Write will write bytes into the SSL connection.
func (c *SSLConn) write(b []byte) (int, error) {
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Write begin",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	defer c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Write end",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	// interlock with Close below
	for {
		c.logger.Printf(
			"%s %-20s %-20s %-20s %-20s",
			"[SSLConn]",
			"Write waiting...",
			fmt.Sprintf("conn=%+v", c.ssl),
			fmt.Sprintf("remote=%+v", c.remote),
			fmt.Sprintf("local=%+v", c.local))
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Write grabbed lock",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	if err := c.handshakeContext(context.Background()); err != nil {
		return 0, err
	}

	c.out.Lock()

	if !c.isHandshakeComplete.Load() {
		c.out.Unlock()
		return 0, c.handshakeErr
	}

	if c.closeNotifySent {
		c.out.Unlock()
		return 0, errShutdown
	}

	if c.isCloseNotifyReceived() {
		c.out.Unlock()
		c.logger.Printf(
			"%s %-20s %-20s %-20s %-20s",
			"[SSLConn]",
			"Write close",
			fmt.Sprintf("conn=%+v", c.ssl),
			fmt.Sprintf("remote=%+v", c.remote),
			fmt.Sprintf("local=%+v", c.local))
		return 0, io.EOF
	}

	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		fmt.Sprintf("Write SSL_pending %+v bytes", libssl.SSLPending(c.ssl.ssl)),
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))

	libssl.SSLClearError()
	n, err := libssl.SSLWriteEx(c.ssl.ssl, b)
	c.out.Unlock()
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		fmt.Sprintf("Wrote %+v bytes", n),
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	if err != nil {
		return n, NewSSLConnError("write", c.remote, err)
	}
	return n, nil
}

// Helper to check shutdown state
// SSL_SENT_SHUTDOWN and SSL_RECEIVED_SHUTDOWN can be set at the same time.
func (c *SSLConn) isCloseNotifyReceived() bool {
	if c.ssl == nil {
		return true
	}
	c.closeNotifyReceived.Store(libssl.SSLGetShutdown(c.ssl.ssl)&libssl.SSL_RECEIVED_SHUTDOWN != libssl.SSL_NO_SHUTDOWN)
	return c.closeNotifyReceived.Load()
}

func (c *SSLConn) Close() error {
	return c.close()
}

// Close will close the SSL connection.
func (c *SSLConn) close() error {
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Close begin",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	defer c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Close end",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	// Interlock with Conn.Write above.
	var x int32
	for {
		c.logger.Printf(
			"%s %-20s %-20s %-20s %-20s",
			"[SSLConn]",
			"Close waiting...",
			fmt.Sprintf("conn=%+v", c.ssl),
			fmt.Sprintf("remote=%+v", c.remote),
			fmt.Sprintf("local=%+v", c.local))
		x = c.activeCall.Load()
		if x&1 != 0 {
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}
	c.logger.Printf(
		"%s %-20s %-20s %-20s %-20s",
		"[SSLConn]",
		"Close grabbed lock",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("remote=%+v", c.remote),
		fmt.Sprintf("local=%+v", c.local))
	if x != 0 {
		c.logger.Printf(
			"%s %-20s %-20s %-20s %-20s",
			"[SSLConn]",
			"Close & write",
			fmt.Sprintf("conn=%+v", c.ssl),
			fmt.Sprintf("remote=%+v", c.remote),
			fmt.Sprintf("local=%+v", c.local))
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		c.ssl.Free()
		c.ssl = nil
		return io.EOF
	}
	c.closeOnce.Do(func() {
		if c.isHandshakeComplete.Load() {
			libssl.SSLClearError()
			if err := c.closeNotify(); err != nil {
				c.closeNotifyErr = fmt.Errorf("tls: failed to send closeNotify alert (but connection was closed anyway): %w", err)
			}
		}
	})
	return c.closeNotifyErr
}

func (c *SSLConn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	var alertErr error
	if !c.closeNotifySent {
		c.logger.Printf(
			"%s %-20s %-20s %-20s %-20s",
			"[SSLConn]",
			"Close-notify begin",
			fmt.Sprintf("conn=%+v", c.ssl),
			fmt.Sprintf("remote=%+v", c.remote),
			fmt.Sprintf("local=%+v", c.local))
		c.logger.Printf(
			"%s %-20s %-20s %-20s %-20s",
			"[SSLConn]",
			"Close-notify end",
			fmt.Sprintf("conn=%+v", c.ssl),
			fmt.Sprintf("remote=%+v", c.remote),
			fmt.Sprintf("local=%+v", c.local))
		if c.isHandshakeComplete.Load() {
			libssl.SSLClearError()
			if !c.isCloseNotifyReceived() {
				alertErr = libssl.SSLShutdown(c.ssl.ssl)
			}
			c.closeNotifySent = true
		}
		if alertErr != nil || c.closeNotifyReceived.Load() {
			c.ssl.Free()
		}
		c.closed.Store(true)
	}
	return alertErr
}

// LocalAddr returns the local network address, if known.
func (c *SSLConn) LocalAddr() net.Addr {
	return c.local
}

// RemoteAddr returns the remote network address, if known.
func (c *SSLConn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *SSLConn) SetDeadline(t time.Time) error {
	c.logger.Printf(
		"%s %-20s %-20s %-20s",
		"[SSLConn]",
		"new deadline",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("addr=%+v", c.remote))
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *SSLConn) SetReadDeadline(t time.Time) error {
	c.logger.Printf(
		"%s %-20s %-20s %-20s",
		"[SSLConn]",
		"new rdeadline",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("addr=%+v", c.remote))
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *SSLConn) SetWriteDeadline(t time.Time) error {
	c.logger.Printf(
		"%s %-20s %-20s %-20s",
		"[SSLConn]",
		"new wdeadline",
		fmt.Sprintf("conn=%+v", c.ssl),
		fmt.Sprintf("addr=%+v", c.remote))
	c.writeDeadline = t
	return nil
}
