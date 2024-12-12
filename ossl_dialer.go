package ossl

import (
	"context"
	"io"
	"net"
	"syscall"
	"time"
)

// Dialer is used for dialing [SSL] connections.
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

	// Config is the dialing Config for [Conn].
	Config *Config

	// Ctx is the [SSLContext] that will be used for creating [SSL] connections. If this is nil, then
	// [Dialer.Dial] will create a new [SSLContext] every invocation.
	Ctx *SSLContext
}

// NewDialer returns the [SSL] dialer configured with [Config].
func NewDialer(opts ...ConfigOption) *Dialer {
	c := DefaultConfig()
	for _, o := range opts {
		o(c)
	}
	return &Dialer{
		Config:  c,
		Timeout: c.Timeout,
	}
}

// emptyCloser is a noop in the case where the caller provides the SSLContext
type emptyCloser struct {
}

func (e emptyCloser) Close() error {
	return nil
}

// Dial specifies a dial function for creating [SSL] connections.
// TODO: should use the context Deadline.
func (d *Dialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	sslCtx, sslCtxCloser, err := d.getSSLCtx()
	if err != nil {
		return nil, err
	}
	ssl, err := NewSSL(sslCtx)
	if err != nil {
		return nil, err
	}
	if err := ssl.DialHost(addr, syscall.AF_INET, 0); err != nil {
		return nil, err
	}
	return NewConn(ssl, sslCtxCloser, d.Config)
}

func (d *Dialer) getSSLCtx() (*SSLContext, io.Closer, error) {
	// if the caller is managing the SSLContext, create a new one that [Conn] will close
	if d.Ctx == nil {
		sslCtx, err := NewSSLContext(d.Config)
		if err != nil {
			return nil, nil, err
		}
		return sslCtx, sslCtx, nil
	}
	// otherwise, we use the supplied sslCtx for creating [SSL] connections and provide an empty
	// closer to [Conn]
	return d.Ctx, emptyCloser{}, nil
}
