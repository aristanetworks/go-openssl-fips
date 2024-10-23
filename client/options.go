package client

import (
	"time"

	"github.com/golang-fips/openssl/v2/client/conn"
)

// TransportOption configures the SSLTransport.
type TransportOption func(*SSLTransport)

// WithTimeout sets the timeout for the request.
func WithTimeout(timeout time.Duration) TransportOption {
	return func(c *SSLTransport) {
		c.Timeout = timeout
	}
}

// WithRequestHeaders adds http.Headers to send with each request.
func WithRequestHeaders(h map[string]string) TransportOption {
	return func(t *SSLTransport) {
		t.Headers = h
	}
}

// WithTLSConfig sets the conn.Config for the SSL connection.
func WithTLSConfig(c *conn.Config) TransportOption {
	return func(t *SSLTransport) {
		t.TLSConfig = c
	}
}
