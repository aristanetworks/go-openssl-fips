package fipstls

import (
	"context"
	"net"
	"syscall"
	"time"
)

var DefaultNetwork = "tcp4"

// Dialer is used for dialing [SSL] connections.
type Dialer struct {
	// Ctx is the [SSLContext] that will be used for creating [SSL] connections.
	Ctx *SSLContext

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

	// ConnTraceEnabled enables debug tracing in the [Conn].
	ConnTraceEnabled bool
}

type DialerOption func(*Dialer)

// WithDialTimeout sets the timeout for the dialer.
func WithDialTimeout(timeout time.Duration) DialerOption {
	return func(d *Dialer) {
		d.Timeout = timeout
	}
}

// WithDialDeadline sets the deadline for the dialer.
func WithDialDeadline(deadline time.Time) DialerOption {
	return func(d *Dialer) {
		d.Deadline = deadline
	}
}

// WithConnTracingEnabled enables tracing for the dialer.
func WithConnTracingEnabled() DialerOption {
	return func(d *Dialer) {
		d.ConnTraceEnabled = true
	}
}

// NewDialer is returns a [Dialer] configured with [DialerOption]. The
// [SSLContext] should not be nil.
func NewDialer(ctx *SSLContext, opts ...DialerOption) *Dialer {
	if ctx == nil {
		panic("cannot create Dialer from nil SSLContext")
	}
	d := &Dialer{Ctx: ctx}
	for _, o := range opts {
		o(d)
	}
	return d
}

// DialContext specifies a dial function for creating [SSL] connections.
// The network must be one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or
// "unix".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := Init(d.Ctx.TLS.LibsslVersion); err != nil {
		return nil, err
	}
	if network == "" {
		network = DefaultNetwork
	}
	bio, err := d.dialBIO(ctx, network, addr)
	if err != nil {
		bio.Close()
		return nil, err
	}
	return d.newConn(bio)
}

// NewGrpcDialFn returns a dialer function for grpc to create [SSL] connections.
// The [SSLContext] should not be nil.
func NewGrpcDialFn(sslCtx *SSLContext, network string, opts ...DialerOption) func(context.Context,
	string) (net.Conn, error) {
	d := NewDialer(sslCtx, opts...)
	if network == "" {
		network = DefaultNetwork
	}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		if err := Init(sslCtx.TLS.LibsslVersion); err != nil {
			return nil, err
		}
		bio, err := d.dialBIO(ctx, network, addr)
		if err != nil {
			bio.Close()
			return nil, err
		}
		return d.newConn(bio)
	}
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
	ctx, err := d.Ctx.New()
	if err != nil {
		ctx.Close()
		return nil, err
	}
	ssl, err := NewSSL(ctx, bio)
	if err != nil {
		ssl.Close()
		ctx.Close()
		return nil, err
	}
	return NewConn(ssl, ctx.closer, d.ConnTraceEnabled)
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
