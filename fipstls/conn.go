package fipstls

import (
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

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// Conn represents a single SSL connection. It inherits configuration options
// from [Context].
type Conn struct {
	ssl *libssl.SSL
	bio *BIO

	// config is the [Config] passed to the constructor
	config *Config

	// closed tracks conn closure state
	closer Closer
	closed atomic.Bool
	// activeCall indicates whether Close has been call in the low bit.
	// the rest of the bits are the number of goroutines in Conn.Write.
	activeCall atomic.Int32
	// read / write mutexes
	in  sync.Mutex
	out sync.Mutex

	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool
	closeErr        error

	// deadlines
	readDeadline      atomicTime
	writeDeadline     atomicTime
	handshakeDeadline atomicTime

	// l is a logger
	l logger
}

var (
	opRead      = "read"
	opWrite     = "write"
	opShutdown  = "close"
	opHandshake = "handshake"
)

type logger interface {
	trace(string, ...any)
}

type noopLogger struct{}

func (noopLogger) trace(string, ...any) {}

type connLogger struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	fd         int
	logger     *log.Logger
}

func (c *connLogger) trace(format string, v ...any) {
	c.logger.Printf(
		"%s %-40s %-20s %-20s %-5s",
		"[fipstls.Conn]",
		fmt.Sprintf(format, v...),
		fmt.Sprintf("local=%+v", c.localAddr),
		fmt.Sprintf("remote=%+v", c.remoteAddr),
		fmt.Sprintf("conn=%+v", c.fd),
	)
}

// NewConn creates a TLS [Conn] from a [Context] and [BIO].
func NewConn(ctx *Context, bio *BIO, tls *Config, trace bool) (*Conn, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	ssl, err := libssl.NewSSL(ctx.Ctx())
	if err != nil {
		libssl.SSLFree(ssl)
		return nil, err
	}
	c := &Conn{
		ssl:    ssl,
		bio:    bio,
		config: tls,
		closer: noopCloser{},
		l:      noopLogger{},
	}
	if err := c.configureBIO(); err != nil {
		libssl.SSLFree(c.ssl)
		return nil, err
	}
	c.closer = newOnceCloser(func() error {
		c.l.trace("Closer.close called")
		libssl.SSLFree(c.ssl)
		return ctx.closer.Close()
	})
	if trace {
		c.l = &connLogger{
			localAddr:  bio.LocalAddr(),
			remoteAddr: bio.RemoteAddr(),
			fd:         bio.FD(),
			logger:     log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile),
		}
	}
	return c, nil
}

func (c *Conn) configureBIO() error {
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	hostname := c.config.ServerName
	if hostname == "" {
		hostname = c.bio.Hostname()
	}
	if err := libssl.SSLConfigureBIO(c.ssl, c.bio.BIO(), hostname); err != nil {
		return err
	}
	return nil
}

func (c *Conn) connect() error {
	libssl.SSLClearError()
	return libssl.SSLConnect(c.ssl)
}

// Handshake initiates a TLS handshake with the peer.
func (c *Conn) Handshake(deadline time.Time) error {
	c.l.trace("Handshake begin")
	defer c.l.trace("Handshake end")
	c.handshakeDeadline.Store(deadline)
	_, err := c.doIO(nil, func(b []byte) (int, error) { return 0, c.connect() }, opHandshake)
	if err != nil {
		c.l.trace("Post-Handshake negotiated protocols: %v", libssl.SSLStatusALPN(c.ssl))
	}
	return err
}

// LocalAddr returns the local address if known.
func (c *Conn) LocalAddr() net.Addr {
	return c.bio.LocalAddr()
}

// RemoteAddr returns the peer address if known.
func (c *Conn) RemoteAddr() net.Addr {
	return c.bio.RemoteAddr()
}

// Read will read bytes into the buffer from the [Conn] connection.
func (c *Conn) read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	libssl.SSLClearError()
	r, n, err := libssl.SSLReadEx(c.ssl, int64(len(b)))
	if err != nil {
		return n, err
	}
	copy(b, r[:n])
	return n, nil
}

// Read will read bytes into the buffer from the [Conn] connection, wrapped in an optional deadline.
func (c *Conn) Read(b []byte) (int, error) {
	c.l.trace("Read begin")
	defer c.l.trace("Read end")
	c.in.Lock()
	defer c.in.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	return c.doIO(b, c.read, opRead)
}

// Write will write bytes from the buffer to the [Conn] connection.
func (c *Conn) write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	libssl.SSLClearError()
	return libssl.SSLWriteEx(c.ssl, b)
}

var ErrShutdown = errors.New("fipstls: protocol is shutdown")

// Write will write bytes from the buffer to the [Conn] connection, wrapped in an optional deadline.
func (c *Conn) Write(b []byte) (int, error) {
	c.l.trace("Write begin")
	defer c.l.trace("Write end")
	// interlock with Close below
	for {
		c.l.trace("Write waiting...")
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)
	c.l.trace("Write grabbed lock")
	c.out.Lock()
	defer c.out.Unlock()
	if c.closeNotifySent {
		// we're done writing
		return 0, ErrShutdown
	}
	return c.doIO(b, c.write, opWrite)
}

// Shutdown will send a close-notify alert to the peer to gracefully shutdown
// the [Conn] connection.
func (c *Conn) shutdown() error {
	if c.closed.Load() {
		return c.closeErr
	}
	libssl.SSLClearError()
	return libssl.SSLShutdown(c.ssl)
}

// Close will attempt to cleanly shutdown the [Conn] connection and free [Conn] and optionally
// [Context] resources if a non-empty context was provided.
func (c *Conn) Close() error {
	c.l.trace("Close begin")
	defer c.l.trace("Close end")
	var x int32
	for {
		c.l.trace("Close waiting...")
		x = c.activeCall.Load()
		if x&1 != 0 {
			if c.closed.Load() {
				c.l.trace("Close connection is closed, returning: %v", c.closeErr)
				return c.closeErr
			}
			c.l.trace("Close connection is not closed, returning: %v", net.ErrClosed)
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}
	c.l.trace("Close grabbed lock")
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		c.l.trace("Force closing to handle Close-during-Write")
		if c.closed.Load() {
			return c.closeErr
		}
		// send done to stop any concurrent reads / writes
		c.closer.Done()
		c.closed.Store(true)
		return c.closer.Close()
	}
	return c.closeNotify()
}

// closeNotify closes the Write side of the connection by sending a close notify shutdown alert
// message to the peer.
func (c *Conn) closeNotify() error {
	c.l.trace("Close-notify begin")
	defer c.l.trace("Close-notify end")
	c.out.Lock()
	defer c.out.Unlock()
	if !c.closeNotifySent && !c.closed.Load() {
		// Set a Write Deadline to prevent possibly blocking forever.
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, c.closeErr = c.doIO(nil, func(b []byte) (int, error) { return 0, c.shutdown() },
			opShutdown)
		c.l.trace("close error is: %v", c.closeErr)
		defer c.closer.Done()
		defer c.closer.Close()
		c.closeNotifySent = true
		c.closed.Store(true)
		// Any subsequent writes will fail.
		c.SetWriteDeadline(time.Now())
	}
	return c.closeErr
}

// SetDeadline sets the read and write deadlines of the [Conn] connection.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

type atomicTime struct {
	v atomic.Value
}

func (t *atomicTime) Store(tm time.Time) {
	t.v.Store(tm)
}

func (t *atomicTime) Load() time.Time {
	if v := t.v.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

// SetReadDeadline sets the deadline for future [SSL.Read] calls
// and any currently-blocked [SSL.Read] call.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.l.trace("New rdeadline")
	c.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline sets the deadline for future [SSL.Write] calls
// and any currently-blocked [SSL.Write] call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.l.trace("New wdeadline")
	c.writeDeadline.Store(t)
	return nil
}

type ioResult struct {
	n   int
	err error
}

// retryResult represents the outcome of handling an SSL error
type retryResult struct {
	retry bool          // should retry the operation
	err   error         // error to return if not retrying
	sleep time.Duration // how long to sleep before retry
}

// retryable processes SSL errors and determines whether to retry operations
func (c *Conn) retryable(err error, kind string) retryResult {
	c.l.trace("%v non-blocking handleSSLError", kind)
	if err == nil {
		return retryResult{false, nil, 0}
	}

	// Handle SSL-specific errors
	c.l.trace("%v non-blocking got %v", kind, libssl.NewOpenSSLError(""))
	if sslErr, ok := err.(*libssl.SSLError); ok {
		switch sslErr.Code {
		case libssl.SSL_ERROR_WANT_READ, libssl.SSL_ERROR_WANT_WRITE:
			c.l.trace("%v non-blocking wants read/write", kind)
			return retryResult{true, nil, time.Millisecond}

		case libssl.SSL_ERROR_ZERO_RETURN:
			c.l.trace("%v non-blocking return zero", kind)
			return retryResult{false, io.EOF, 0}

		case libssl.SSL_ERROR_SSL:
			switch kind {
			case opShutdown:
				c.l.trace("%s non-blocking forced closed", kind)
				return retryResult{false, nil, 0}
			case opHandshake:
				// Check verification error first
				if verifyErr := libssl.SSLGetVerifyResult(c.ssl); verifyErr != nil {
					return retryResult{false, verifyErr, 0}
				}
			case opRead:
				// Check verification error first
				if verifyErr := libssl.SSLGetVerifyResult(c.ssl); verifyErr != nil {
					return retryResult{false, verifyErr, 0}
				}
				// otherwise, retry assuming its transient and ignore the error
				// as it might be "SSL routines::sslv3 alert bad record mac" during
				// connection closure.
				return retryResult{true, nil, 0}
			}
			// For other operations, fallthrough to default error handling

		case libssl.SSL_ERROR_SYSCALL:
			// Special handling for syscall errors
			errno, sockErr := syscall.GetsockoptInt(c.bio.FD(), syscall.SOL_SOCKET,
				syscall.SO_ERROR)
			if sockErr != nil {
				c.l.trace("%s failed! could not get errno: %v", kind, errno)
				return retryResult{false, newConnError(kind, c.bio.RemoteAddr(), sockErr), 0}
			}

			if errno != 0 {
				c.l.trace("%s failed! errno: %v openssl error: %s", kind, errno,
					libssl.NewOpenSSLError(""))
				return retryResult{false, newConnError(kind, c.bio.RemoteAddr(), err), 0}
			}

			// For other zero errno cases, retry
			return retryResult{true, nil, time.Millisecond}

		case libssl.SSL_ERROR_WANT_CONNECT:
			return retryResult{true, nil, time.Millisecond * 10}

		case libssl.SSL_ERROR_WANT_ACCEPT:
			return retryResult{true, nil, time.Millisecond * 10}

		case libssl.SSL_ERROR_WANT_X509_LOOKUP:
			// Certificate lookup in progress
			return retryResult{true, nil, time.Millisecond * 100}
		}
	}

	// Default error handling for non-SSL errors or unhandled SSL errors
	c.l.trace("%v error: %v", kind, err)
	return retryResult{false, newConnError(kind, c.bio.RemoteAddr(), err), 0}
}

// ioLoop executes an SSL operation with proper error handling and retries
func (c *Conn) ioLoop(b []byte, op func([]byte) (int, error), kind string, done <-chan struct{},
	outCh chan<- ioResult) {
	var retries int
	maxRetries := 1000 // Prevent infinite loops

	for retries < maxRetries {
		select {
		case <-done:
			return
		default:
			r, err := op(b)

			retry := c.retryable(err, kind)
			if !retry.retry {
				select {
				case outCh <- ioResult{r, retry.err}:
				case <-done:
				}
				return
			}

			// Handle retry with optional sleep
			if retry.sleep > 0 {
				time.Sleep(retry.sleep)
			}

			retries++
		}
	}

	// Max retries exceeded
	select {
	case outCh <- ioResult{0, fmt.Errorf("%s: max retries exceeded", kind)}:
	case <-done:
	}
}

func (c *Conn) doIO(b []byte, op func([]byte) (int, error), kind string) (int, error) {
	c.l.trace("%v non-blocking begin", kind)
	defer c.l.trace("%v non-blocking end", kind)

	done := make(chan struct{})
	outCh := make(chan ioResult, 1)

	// Start operation loop
	go c.ioLoop(b, op, kind, done, outCh)

	// Handle deadline
	var timer *time.Timer
	var timeoutCh <-chan time.Time

	var deadline time.Time
	switch kind {
	case opHandshake:
		deadline = c.handshakeDeadline.Load()
	case opWrite, opShutdown:
		deadline = c.writeDeadline.Load()
	case opRead:
		deadline = c.readDeadline.Load()
	}

	if !deadline.IsZero() {
		if timeout := time.Until(deadline); timeout > 0 {
			timer = time.NewTimer(timeout)
			timeoutCh = timer.C
		} else {
			close(done)
			return 0, os.ErrDeadlineExceeded
		}
		defer timer.Stop()
	}

	// Wait for result, timeout or close
	select {
	case r, ok := <-outCh:
		if !ok {
			return 0, net.ErrClosed
		}
		return r.n, r.err
	case <-timeoutCh:
		close(done)
		return 0, os.ErrDeadlineExceeded
	case <-c.closer.Done():
		close(done)
		return 0, c.closeErr
	}
}
