package conn

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
	// timeout
	timeout time.Duration
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
	// Configure the client to abort the handshake if certificate verification fails
	libssl.SSLCtxSetVerify(sslCtx, libssl.SSL_VERIFY_PEER, libssl.SslVerifyCallback{})
	// Use the default trusted certificate store
	if err := libssl.SSLCtxSetDefaultVerifyPaths(sslCtx); err != nil {
		return nil, err
	}

	// Set minimum TLS version to TLSv1.2
	if err := libssl.SSLCtxSetMinProtoVersion(sslCtx, libssl.TLS1_2_VERSION); err != nil {
		return nil, err
	}
	ssl, err := libssl.NewSSL(sslCtx)
	if err != nil {
		return nil, err
	}
	// Set the SNI hostname
	if err := libssl.SSLSetTLSExtHostName(ssl, host.Hostname()); err != nil {
		return nil, err
	}
	// Set the hostname for certificate verification
	if err := libssl.SSLSet1Host(ssl, host.Hostname()); err != nil {
		return nil, err
	}

	// set up TCP connection, similar to default http.Client stack
	conn, err := net.Dial("tcp", net.JoinHostPort(host.Hostname(), host.Port()))
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
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
	if err := libssl.SSLConnectWithRetry(ssl, timeout); err != nil {
		return nil, err
	}
	return &SSLConn{sslCtx: sslCtx, ssl: ssl, conn: conn, fd: fd, timeout: timeout}, nil
}

// Read will read into bytes from the SSL connection.
func (c *SSLConn) Read(b []byte) (int, error) {
	// r, n, err := libssl.SSLReadEx(c.ssl, len(b))
	// if err != nil && libssl.SSLGetError(c.ssl, 0) != libssl.SSL_ERROR_ZERO_RETURN {
	// 	return n, err
	// }
	r, n, err := libssl.SSLReadExWithRetry(c.ssl, len(b), c.timeout)
	if err != nil {
		return n, err
	}
	copy(b, r[:n])
	return n, nil
}

// Write will write bytes into the SSL connection.
func (c *SSLConn) Write(b []byte) (int, error) {
 	return libssl.SSLWriteExWithRetry(c.ssl, b, c.timeout)
}

// Close will close the SSL connection.
func (c *SSLConn) Close() error {
	if err := libssl.SSLShutdownWithRetry(c.ssl, c.timeout); err != nil {
		libssl.SSLFree(c.ssl)
		libssl.SSLCtxFree(c.sslCtx)
	}
	return c.conn.Close()
}
