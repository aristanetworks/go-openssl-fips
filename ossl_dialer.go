package ossl

import (
	"context"
	"net"
	"syscall"
	"time"
)

// Dialer is used for dialing [SSL] connections.
type Dialer struct {
	// Ctx is the [Context] that will be used for creating [SSL] connections.
	Ctx *Context
}

// DialContext specifies a dial function for creating [SSL] connections.
// The network must be "tcp" (defaults to "tcp4"), "tcp4", "tcp6", or "unix".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
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
	return NewConn(ssl, ctx.closer, ctx.TLS.DialTraceEnabled)
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
//
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
func (d *Dialer) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.Ctx.TLS.DialTimeout != 0 { // including negative, for historical reasons
		earliest = now.Add(d.Ctx.TLS.DialTimeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return minNonzeroTime(earliest, d.Ctx.TLS.DialDeadline)
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
