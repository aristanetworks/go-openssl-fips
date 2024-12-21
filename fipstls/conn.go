package fipstls

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// Conn represents a single SSL connection. It inherits configuration options
// from [Context].
type Conn struct {
	ssl *libssl.SSL
	bio *BIO
	// closed tracks conn closure state
	closer Closer
	closed atomic.Bool

	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool
	closeErr        error

	// deadlines
	readDeadline      time.Time
	writeDeadline     time.Time
	handshakeDeadline time.Time

	// logger
	logger *log.Logger

	// net
	localAddr  net.Addr
	remoteAddr net.Addr

	// enableTrace
	enableTrace bool
}

var (
	opRead      = "read"
	opWrite     = "write"
	opShutdown  = "close"
	opHandshake = "handshake"
)

type opFunc func([]byte) (int, error)

func (c *Conn) trace(msg string) {
	if !c.enableTrace {
		return
	}
	c.logger.Printf(
		"%s %-40s %-20s %-20s %-5s",
		"[fipstls.Conn]",
		msg,
		fmt.Sprintf("local=%+v", c.bio.LocalAddr()),
		fmt.Sprintf("remote=%+v", c.bio.LocalAddr()),
		fmt.Sprintf("conn=%+v", c.bio.FD()),
	)
}

// NewConn creates a TLS [Conn] from a [Context] and [BIO].
func NewConn(ctx *Context, bio *BIO, deadline time.Time, trace bool) (*Conn, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	ssl, err := libssl.NewSSL(ctx.Ctx())
	if err != nil {
		libssl.SSLFree(ssl)
		return nil, err
	}
	c := &Conn{
		ssl:               ssl,
		bio:               bio,
		closer:            noopCloser{},
		handshakeDeadline: deadline,
		enableTrace:       trace,
	}
	if err := c.configureBIO(c.bio); err != nil {
		libssl.SSLFree(c.ssl)
		return nil, err
	}
	c.closer = &onceCloser{
		closeFunc: func() error {
			defer ctx.Close()
			return libssl.SSLFree(c.ssl)
		},
	}
	if c.enableTrace {
		c.logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile|log.Lmicroseconds)
	}
	return c, nil
}

func (c *Conn) configureBIO(b *BIO) error {
	c.bio = b
	if err := libssl.SSLConfigureBIO(c.ssl, b.BIO(), b.Hostname()); err != nil {
		return err
	}
	return nil
}

func (c *Conn) connect() error {
	err := libssl.SSLConnect(c.ssl)
	if err == nil {
		return err
	}
	return nil
}

// Handshake initiates a TLS handshake with the peer.
func (c *Conn) Handshake() error {
	c.trace("Handshake begin")
	defer c.trace("Handshake end")
	_, err := c.doNonBlockingIO(nil, opHandshake)

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
	if c.closer.Err() != nil {
		return 0, c.closer.Err()
	}
	r, n, err := libssl.SSLReadEx(c.ssl, int64(len(b)))
	if err != nil {
		if err := libssl.SSLGetVerifyResult(c.ssl); err != nil {
			return n, err
		}
		return n, err
	}
	copy(b, r[:n])
	return n, nil
}

// Read will read bytes into the buffer from the [Conn] connection, wrapped in an optional deadline.
func (c *Conn) Read(b []byte) (int, error) {
	c.trace("Read begin")
	defer c.trace("Read end")
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	return c.doNonBlockingIO(b, opRead)
}

// Write will write bytes from the buffer to the [Conn] connection.
func (c *Conn) write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, c.closer.Err()
	}
	return libssl.SSLWriteEx(c.ssl, b)
}

var ErrShutdown = errors.New("fipstls: protocol is shutdown")

// Write will write bytes from the buffer to the [Conn] connection, wrapped in an optional deadline.
func (c *Conn) Write(b []byte) (int, error) {
	c.trace("Write begin")
	defer c.trace("Write end")
	if c.closeNotifySent {
		// we're done writing
		return 0, ErrShutdown
	}
	return c.doNonBlockingIO(b, opWrite)
}

// Shutdown will send a close-notify alert to the peer to gracefully shutdown
// the [Conn] connection.
func (c *Conn) shutdown() error {
	if c.closed.Load() {
		return c.closer.Err()
	}
	return libssl.SSLShutdown(c.ssl)
}

// Close will attempt to cleanly shutdown the [Conn] connection and free [Conn] and optionally
// [Context] resources if a non-empty context was provided.
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
		_, c.closeErr = c.doNonBlockingIO(nil, opShutdown)
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

func (c *Conn) doNonBlockingIO(b []byte, opKind string) (int, error) {
	c.trace(fmt.Sprintf("%v non-blocking begin", opKind))
	defer c.trace(fmt.Sprintf("%v non-blocking end", opKind))

	d := time.Time{}
	var op opFunc
	switch opKind {
	case opRead:
		d = c.readDeadline
		op = c.read
	case opWrite:
		d = c.writeDeadline
		op = c.write
	case opShutdown:
		d = c.writeDeadline
		op = func([]byte) (int, error) { return 0, c.shutdown() }
	case opHandshake:
		d = c.handshakeDeadline
		op = func([]byte) (int, error) { return 0, c.connect() }
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
				continue
			case libssl.SSL_ERROR_ZERO_RETURN:
				c.trace(fmt.Sprintf("%v non-blocking return zero", opKind))
				return result, io.EOF
			case libssl.SSL_ERROR_SSL:
				// check if its a verification error
				if err := libssl.SSLGetVerifyResult(c.ssl); err != nil {
					return result, err
				}
				if opKind == opShutdown {
					// if we got an SSL_ERROR_SSL during a second shutdown, that means the peer
					// did not do a clean shutdown.
					c.trace(fmt.Sprintf("%s non-blocking forced closed", opKind))
					// otherwise we ignore it
					return result, nil
				}
			default:
				c.trace(fmt.Sprintf("%v non-blocking error: %v", opKind, err))
				return result, newConnError(opKind, c.remoteAddr, err)
			}
		}
	}
}
