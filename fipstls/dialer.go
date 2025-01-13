package fipstls

import (
	"context"
	"net"
	"time"
)

// DefaultNetwork is the default network to dial connections over.
var DefaultNetwork = "tcp4"

// Dialer is used for dialing [Conn] connections.
type Dialer struct {
	// TLS is used for configuring the [Context] used in creating [Conn] connections.
	TLS *Config

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

	// Network is one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or "unix".
	Network string
}

// DialOption is used for configuring the [Dialer].
type DialOption func(*Dialer)

// WithDialTimeout sets the timeout for the dialer.
func WithDialTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) {
		d.Timeout = timeout
	}
}

// WithDialDeadline sets the deadline for the dialer.
func WithDialDeadline(deadline time.Time) DialOption {
	return func(d *Dialer) {
		d.Deadline = deadline
	}
}

// WithConnTracingEnabled enables tracing for the dialer.
func WithConnTracingEnabled() DialOption {
	return func(d *Dialer) {
		d.ConnTraceEnabled = true
	}
}

// WithNetwork can be one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or "unix".
func WithNetwork(network string) DialOption {
	return func(d *Dialer) {
		d.Network = network
	}
}

// NewDialer is returns a [Dialer] configured with [DialOption].
func NewDialer(tls *Config, opts ...DialOption) *Dialer {
	if tls == nil {
		tls = NewDefaultConfig()
	}
	d := &Dialer{TLS: tls, Network: DefaultNetwork}
	for _, o := range opts {
		o(d)
	}
	return d
}

// DialContext specifies a dial function for creating [Conn] connections.
// The network must be one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or
// "unix".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "" {
		network = d.Network
	}
	bio, err := d.dialBIO(ctx, network, addr)
	if err != nil {
		bio.Close()
		return nil, err
	}
	return d.newConn(bio)
}

// NewGrpcDialFn returns a dialer function for grpc to create [Conn] connections.
// The [Context] should not be nil.
func NewGrpcDialFn(tls *Config, opts ...DialOption) (func(context.Context,
	string) (net.Conn, error), error) {
	if tls == nil {
		tls = NewDefaultConfig()
	}
	d := NewDialer(tls, opts...)
	// Set H2 as the protocol
	d.TLS.NextProtos = []string{"h2"}
	return func(ctx context.Context, addr string) (net.Conn, error) {
		bio, err := d.dialBIO(ctx, d.Network, addr)
		if err != nil {
			bio.Close()
			return nil, err
		}
		return d.newConn(bio)
	}, nil
}

type dialResult struct {
	bio *BIO
	err error
}

func (d *Dialer) dialBIO(ctx context.Context, network, addr string) (*BIO, error) {
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	ch := make(chan dialResult)
	go func() {
		// create non-blocking BIO
		b, err := NewBIO(addr, network, SOCK_NONBLOCK)
		ch <- dialResult{b, err}
	}()
	select {
	case <-ctx.Done():
		return &BIO{closer: noopCloser{}}, ctx.Err()
	case b := <-ch:
		if b.err != nil {
			return b.bio, b.err
		}
		return b.bio, nil
	}
}

func (d *Dialer) newConn(bio *BIO) (net.Conn, error) {
	ctx, err := NewCtx(d.TLS)
	if err != nil {
		ctx.Close()
		return nil, err
	}
	conn, err := NewConn(ctx, bio, d.Deadline, d.ConnTraceEnabled)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
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
