package client

import (
	"net"
	"net/url"
	"time"

	"github.com/golang-fips/openssl/v2/libssl"
)

// SSLConn is used for writing to and reading from a libssl SSL connection.
type SSLConn struct {
	sslCtx *libssl.SslCtx
	ssl    *libssl.Ssl
	// conn is the underlying TCP connection
	conn net.Conn
	// fd is a duplicate file descriptor belonging to the TCP connection
	fd int
}

// NewSSLConn creates a new SSL connection to the host.
func NewSSLConn(host *url.URL, timeout time.Duration) (*SSLConn, error) {
	// set up TLS client connection context
	method, err := libssl.NewTLSClientMethod()
	if err != nil {
		return nil, err
	}
	sslCtx, err := libssl.NewSSLCtx(method)
	if err != nil {
		return nil, err
	}
	ssl, err := libssl.NewSSL(sslCtx)
	if err != nil {
		return nil, err
	}

	// set up TCP connection, similar to default http.Client stack
	conn, err := net.Dial("tcp", net.JoinHostPort(host.Hostname(), host.Port()))
	if err != nil {
		return nil, err
	}

	// Get the raw file descriptor (this is a duplicate fd)
	file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())

	// Set the SSL fd to the TCP fd dup
	if err := libssl.SetSSLFd(ssl, fd); err != nil {
		return nil, err
	}

	// Create the TLS connection
	if err := libssl.SSLConnect(ssl); err != nil {
		return nil, err
	}

	return &SSLConn{sslCtx: sslCtx, ssl: ssl, conn: conn, fd: fd}, nil
}

// Read will read into bytes from the SSL connection.
func (c *SSLConn) Read(b []byte) (int, error) {
	r, n, err := libssl.SSLReadEx(c.ssl, len(b))
	if err != nil {
		if libssl.SSLGetError(c.ssl, 0) == libssl.SSL_ERROR_ZERO_RETURN {
			// Server closed connection gracefully
			return n, nil
		}
		return n, err
	}
	copy(b, r[:n])
	return len(b), nil
}

// Write will write bytes into the SSL connection.
func (c *SSLConn) Write(b []byte) (int, error) {
 	return libssl.SSLWriteEx(c.ssl, b)
}

// Close will close the SSL connection.
func (c *SSLConn) Close() error {
	if err := libssl.SSLShutdown(c.ssl); err != nil {
		libssl.SSLCtxFree(c.sslCtx)
		libssl.SSLFree(c.ssl)
	}
	// Closing the TCP conn will close the underlying fd
	return c.conn.Close()
}
