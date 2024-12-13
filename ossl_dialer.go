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

// NewDialer returns the [SSL] dialer configured with [Config]. If [SSLContext] is nil, then
// [Dialer.DialContext] will create one that will be freed in [Conn.Close].
func NewDialer(ctx *SSLContext, opts ...ConfigOption) *Dialer {
	c := DefaultConfig()
	for _, o := range opts {
		o(c)
	}
	return &Dialer{
		Ctx:     ctx,
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

// DialContext specifies a dial function for creating [SSL] connections.
// The network must be "tcp" (defaults to "tcp4"), "tcp4", "tcp6", or "unix".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := Init(d.Config.LibsslVersion); err != nil {
		return nil, err
	}
	bio, err := d.dialBIO(ctx, network, addr)
	if err != nil {
		bio.Close()
		return nil, err
	}
	return d.newConn(bio)
}

func (d *Dialer) dialBIO(ctx context.Context, network, addr string) (*BIO, error) {
	family, err := parseNetwork(network)
	if err != nil {
		return nil, err
	}
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}

	type bioResult struct {
		bio *BIO
		err error
	}
	ch := make(chan bioResult)
	go func() {
		b, err := NewBIO(addr, family, 0)
		ch <- bioResult{b, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b := <-ch:
		if b.err != nil {
			return nil, b.err
		}
		return b.bio, nil
	}
}

func parseNetwork(network string) (int, error) {
	switch network {
	case "tcp", "tcp4":
		return syscall.AF_INET, nil
	case "tcp6":
		return syscall.AF_INET6, nil
	case "unix":
		return syscall.AF_UNIX, nil
	default:
		return 0, net.UnknownNetworkError(network)
	}
}

func (d *Dialer) newConn(bio *BIO) (net.Conn, error) {
	ctx, closeCtx, err := d.getSSLCtx()
	if err != nil {
		closeCtx.Close()
		return nil, err
	}
	ssl, err := NewSSL(ctx, bio)
	if err != nil {
		ssl.Close()
		closeCtx.Close()
		return nil, err
	}
	return NewConn(ssl, closeCtx, d.Config)
}

func (d *Dialer) getSSLCtx() (*SSLContext, io.Closer, error) {
	// if no SSLContext is provided, create a new one that [Conn] will close
	if d.Ctx == nil {
		sslCtx, err := NewSSLContext(d.Config)
		if err != nil {
			return nil, sslCtx, err
		}
		return sslCtx, sslCtx, nil
	}
	// otherwise, we use the supplied sslCtx for creating [SSL] connections and provide an empty
	// [io.Closer] to [Conn]
	return d.Ctx, emptyCloser{}, nil
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
//
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (d *Dialer) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(d.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return minNonzeroTime(earliest, d.Deadline)
}

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}
