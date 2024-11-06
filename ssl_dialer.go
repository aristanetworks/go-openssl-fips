package client

import (
	"context"
	"net"
	"time"
)

// SSLDialer holds options for both SSL_CTX and SSL struct and DialTLSContext
type SSLDialer struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. If Deadline is also set, it may fail
	// earlier.
	//
	// The default is no timeout.
	//
	// When using TCP and dialing a host name with multiple IP
	// addresses, the timeout may be divided between them.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	Timeout time.Duration

	// Deadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	Deadline time.Time

	// Cancel is an optional channel whose closure indicates that
	// the dial should be canceled. Not all types of dials support
	// cancellation.
	//
	// Deprecated: Use DialContext instead.
	Cancel <-chan struct{}

	// TLSConfig is the dialing Config for ossl.Conn
	TLSConfig *Config

	// SSLContext
	ctx *SSLContext
}

// DefaultDialer returns the default OpenSSL TLS dialer.
func DefaultDialer(ctx *SSLContext, c *Config) *SSLDialer {
	if c == nil {
		c = DefaultConfig()
	}
	return &SSLDialer{
		ctx:       ctx,
		TLSConfig: c,
		Timeout:   30 * time.Second,
	}
}

// DialTLSContext specifies an optional dial function for creating
// TLS connections for non-proxied HTTPS requests.
//
// If DialTLSContext is nil (and the deprecated DialTLS below is also nil),
// DialContext and TLSClientConfig are used.
//
// If DialTLSContext is set, the Dial and DialContext hooks are not used for HTTPS
// requests and the TLSClientConfig and TLSHandshakeTimeout
// are ignored. The returned net.Conn is assumed to already be
// past the TLS handshake.
func (d *SSLDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// log.Printf("Starting dial to %s", addr)
	// defer log.Printf("Completed dial to %s", addr)
	// dialer := net.Dialer{
	// 	Timeout:  d.Timeout,
	// 	Deadline: d.Deadline,
	// 	Cancel:   d.Cancel,
	// }
	// conn, err := dialer.DialContext(ctx, network, addr)
	// if err != nil {
	// 	return nil, err
	// }
	return NewConn(d.ctx, addr, d.TLSConfig)
}
