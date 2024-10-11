package client

import (
	"fmt"
	"net"
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

// NewSSLConn creates a new SSL connection for the host on port 443.
func NewSSLConn(host string, timeout time.Duration) (*SSLConn, error) {
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
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, 443))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get file descriptor (this is a duplicate fd)
	file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())

	// Set the SSL fd to this TCP fd
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
func (c *SSLConn) Read(b []byte) (n int, err error) {
	// TODO: this should be SSLReadEx for OpenSSL >= 1.1.1
	// TODO: this should loop to read chunks of response
	resp, err := libssl.SSLRead(c.ssl, 1024)
	if err != nil {
		return 0, err
	}
	copy(b, resp)
	return len(b), nil
}

// Write will write bytes into the SSL connection.
func (c *SSLConn) Write(b []byte) (n int, err error) {
	// TODO: this should be SSLWriteEx for OpenSSL >= 1.1.1
	if err := libssl.SSLWrite(c.ssl, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close will close the SSL connection.
func (c *SSLConn) Close() error {
	libssl.SSLCtxFree(c.sslCtx)
	libssl.SSLFree(c.ssl)
	// TODO: need to figure out how to close c.fd
	return c.conn.Close()
}
