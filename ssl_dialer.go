package ossl

import (
	"context"
	"net"
	"syscall"
	"time"
)

// Dialer holds options for both SSL_CTX and SSL struct and DialTLSContext
type Dialer struct {
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

	// Config is the dialing Config for [Conn]
	Config *Config

	// SSLContext
	ctx *SSLContext
}

// DefaultDialer returns the default OpenSSL TLS dialer.
func DefaultDialer(ctx *SSLContext, c *Config) *Dialer {
	if c == nil {
		c = DefaultConfig()
	}
	return &Dialer{
		ctx:     ctx,
		Config:  c,
		Timeout: 30 * time.Second,
	}
}

// DialFn specifies a dial function for creating TLS connections.
// TODO: should use the context Deadline
func (d *Dialer) DialFn(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ssl, err := NewSSL(d.ctx, d.Config)
	if err != nil {
		return nil, err
	}
	if err := ssl.DialHost(host, port, syscall.AF_INET, 0); err != nil {
		return nil, err
	}
	return NewConn(ssl, addr, d.Config)
}

func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialFn(ctx, addr)
}
