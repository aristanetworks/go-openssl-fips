package fipstls

import (
	"context"
	"io"
	"log"
	"net"
	"time"
)

// DefaultNetwork is the default network to dial connections over.
var DefaultNetwork = "tcp4"

const dialLogPrefix = "[fipstls.Dialer]"

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

	// Network is one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or "unix".
	Network string

	// Logger will be used to print logs at 3 verbosity levels:
	// [LevelError], [LevelInfo], and [LevelDebug].
	Logger Logger
}

// DialOption is used for configuring the [Dialer].
type DialOption func(*Dialer)

// WithTimeout sets the timeout for the dialer.
func WithTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) {
		d.Timeout = timeout
	}
}

// WithDeadline sets the deadline for the dialer.
func WithDeadline(deadline time.Time) DialOption {
	return func(d *Dialer) {
		d.Deadline = deadline
	}
}

// WithNetwork can be one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or "unix".
func WithNetwork(network string) DialOption {
	return func(d *Dialer) {
		d.Network = network
	}
}

// WithLogging enables logging with the specified level and prefix and will write
// logs by calling the stdlib logging [log.Logger.Printf].
func WithLogging(prefix string, level LogLevel, w io.Writer) DialOption {
	return func(d *Dialer) {
		d.Logger = &DefaultLogger{
			Prefix:     prefix + dialLogPrefix,
			Level:      level,
			LoggerFunc: log.New(w, "", log.LstdFlags).Printf,
		}
	}
}

// WithLoggerFunc enables logging with the [Logger] interface. The
// [DefaultLogger.LoggerFunc] can be overridden in order to write to external
// logging package functions, like glog.Info.
func WithLogger(l Logger) DialOption {
	return func(d *Dialer) {
		d.Logger = l
	}
}

// NewDialer is returns a [Dialer] configured with [DialOption].
func NewDialer(tls *Config, opts ...DialOption) *Dialer {
	if tls == nil {
		tls = newDefaultConfig()
	}
	// Create with disabled logging by default
	d := &Dialer{TLS: tls, Network: DefaultNetwork, Logger: &noopLogger{}}
	for _, o := range opts {
		o(d)
	}
	return d
}

// DialContext specifies a dial function for creating [Conn] connections.
// The network must be one of "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), or
// "unix".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.Network = network
	if d.Network == "" {
		d.Network = DefaultNetwork
	}
	if d.Logger == nil {
		d.Logger = noopLogger{}
	}
	return d.dial(ctx, addr)
}

// NewDialContext returns a dial function for grpc to create [Conn] connections.
func NewDialContext(tls *Config, opts ...DialOption) func(context.Context,
	string) (net.Conn, error) {
	if tls == nil {
		tls = newDefaultConfig()
	}
	// Set H2 as the protocol
	tls.NextProtos = []string{"h2"}
	d := NewDialer(tls, opts...)
	return d.dial
}

type dialResult struct {
	bio *BIO
	err error
}

func (d *Dialer) dial(ctx context.Context, addr string) (net.Conn, error) {
	d.Logger.Logf(LogLevelInfo, "Dialing with FIPS Mode = %v, Version = %s, ProviderInfo = %s",
		FIPSMode(), Version(), ProviderInfo())
	bio, err := d.dialBIO(ctx, d.Network, addr)
	if err != nil {
		bio.Close()
		return nil, err
	}
	return d.newConn(bio)
}

func (d *Dialer) dialBIO(ctx context.Context, network, addr string) (*BIO, error) {
	d.Logger.Logf(LogLevelInfo, "Dialing '%s:%s' begin", network, addr)
	defer d.Logger.Logf(LogLevelInfo, "Dialing '%s:%s' end", network, addr)
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
			d.Logger.Logf(LogLevelErr, "Creating BIO failed: %v", b.err)
			return b.bio, b.err
		}
		return b.bio, nil
	}
}

func (d *Dialer) newConn(bio *BIO) (net.Conn, error) {
	d.Logger.Logf(LogLevelInfo, "New connection: %s", bio)
	ctx, err := NewCtx(d.TLS)
	if err != nil {
		d.Logger.Logf(LogLevelErr, "Creating context failed: %v", err)
		ctx.Close()
		return nil, err
	}
	conn, err := NewConn(ctx, bio, d.TLS, d.Logger)
	if err != nil {
		d.Logger.Logf(LogLevelErr, "Creating connection failed: %v", err)
		conn.Close()
		return nil, err
	}
	if err := conn.Handshake(d.Deadline); err != nil {
		d.Logger.Logf(LogLevelErr, "Handshake failed: %v", err)
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
