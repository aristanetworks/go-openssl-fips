package ossl

import (
	"path/filepath"
	"time"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// TLS version constants.
type TLSVersion int

const (
	TLSv1  = libssl.TLS1_VERSION
	TLSv11 = libssl.TLS1_1_VERSION
	TLSv12 = libssl.TLS1_2_VERSION
	TLSv13 = libssl.TLS1_3_VERSION
)

// Method represents TLS method modes.
type Method int

const (
	// DefaultMethod is the TLS method
	DefaultMethod Method = iota

	// ClientMethod is the TLS client method
	ClientMethod

	// ServerMethod is the TLS server method
	ServerMethod
)

// VerifyMode represents certificate verification modes
type VerifyMode int

const (
	// VerifyNone will skip certificate verification (insecure)
	VerifyNone VerifyMode = iota
	// VerifyPeer will verify peer certificate
	VerifyPeer
	// VerifyFailIfNoPeerCert will fail if peer doesn't present a certificate
	VerifyFailIfNoPeerCert
	// VerifyClientOnce will verify client certificate only once
	VerifyClientOnce
	// VerifyPostHandshake will do post-handshake verification
	VerifyPostHandshake
)

// X509VerifyFlags represents certificate verification flags.
type X509VerifyFlags uint32

const (
	// X509CheckTimeValidity checks certificate time validity
	X509CheckTimeValidity X509VerifyFlags = 1 << iota
	// X509CheckCRL checks certificate revocation
	X509CheckCRL
	// X509CheckCRLAll checks entire certificate chain for revocation
	X509CheckCRLAll
	// X509StrictMode enables strict certificate checking
	X509StrictMode
	// X509AllowPartialChains allows partial certificate chains
	X509AllowPartialChains
	// X509TrustedFirst prefers trusted certificates when building chain
	X509TrustedFirst
)

type TLSConfig struct {
	// LibsslVersion is the libssl version to dynamically load.
	LibsslVersion string

	// CaFile is the path to a file of CA certificates in PEM format.
	CaFile string

	// CaPath is the path to a directory containing CA certificates in PEM format.
	CaPath string

	// MinVersion is the minimum TLS version to accept.
	MinVersion int64

	// MaxVersion is the maximum TLS version to use.
	MaxVersion int64

	// TLSMethod is the TLS method to use.
	Method Method

	// VerifyMode controls how peer certificates are verified.
	VerifyMode VerifyMode

	// CertificateChecks controls X.509 certificate verification.
	CertificateChecks X509VerifyFlags

	// SessionTicketsDisabled disables session ticket support.
	SessionTicketsDisabled bool

	// SessionCacheDisabled disables session caching.
	SessionCacheDisabled bool

	// CompressionDisabled disables session caching.
	CompressionDisabled bool

	// RenegotiationDisabled disables all renegotiation.
	RenegotiationDisabled bool

	// DialTimeout is the maximum amount of time a dial will wait for
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
	DialTimeout time.Duration

	// DialDeadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	DialDeadline time.Time

	// TraceEnabled enables debug tracing in the [Conn].
	TraceEnabled bool
}

// DefaultConfig returns a [TLSConfig] with sane default options. The default context is uninitialized.
func NewDefaultTLS() *TLSConfig {
	return &TLSConfig{
		Method:            ClientMethod,
		MinVersion:        TLSv12,
		VerifyMode:        VerifyPeer,
		CertificateChecks: X509CheckTimeValidity,
	}
}

// TLSOption is a functional option for configuring [TLSConfig].
type TLSOption func(*TLSConfig)

// NewTLS creates a new [TLSConfig] with the given options.
func NewTLS(opts ...TLSOption) *TLSConfig {
	cfg := NewDefaultTLS()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithLibsslVersion sets the libssl version to dynamically load.
func WithLibsslVersion(version string) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.LibsslVersion = version
	}
}

// WithCaFile sets the path to a file of CA certificates in PEM format.
func WithCaFile(path string) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.CaPath = filepath.Dir(path)
		cfg.CaFile = path
	}
}

// WithMinVersion sets the minimum TLS version to accept.
func WithMinVersion(version int64) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.MinVersion = version
	}
}

// WithMaxVersion sets the maximum TLS version to use.
func WithMaxVersion(version int64) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.MaxVersion = version
	}
}

// WithMethod sets the TLS method to use.
func WithMethod(method Method) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.Method = method
	}
}

// WithVerifyMode sets the certificate verification mode.
func WithVerifyMode(mode VerifyMode) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.VerifyMode = mode
	}
}

// WithCertificateChecks sets the certificate verification flags.
func WithCertificateChecks(flags X509VerifyFlags) TLSOption {
	return func(cfg *TLSConfig) {
		cfg.CertificateChecks = flags
	}
}

// WithSessionTicketsDisabled disables session ticket support.
func WithSessionTicketsDisabled() TLSOption {
	return func(cfg *TLSConfig) {
		cfg.SessionTicketsDisabled = true
	}
}

// WithSessionCacheDisabled disables session caching.
func WithSessionCacheDisabled() TLSOption {
	return func(cfg *TLSConfig) {
		cfg.SessionCacheDisabled = true
	}
}

// WithCompressionDisabled disables compression.
func WithCompressionDisabled() TLSOption {
	return func(cfg *TLSConfig) {
		cfg.CompressionDisabled = true
	}
}

// WithRenegotiationDisabled disables all renegotiation.
func WithRenegotiationDisabled() TLSOption {
	return func(cfg *TLSConfig) {
		cfg.RenegotiationDisabled = true
	}
}

// WithDialTimeout is the timeout used for the [Dialer].
func WithDialTimeout(t time.Duration) TLSOption {
	return func(d *TLSConfig) {
		d.DialTimeout = t
	}
}

// WithDialTimeout is the deadline used for the [Dialer].
func WithDialDeadline(t time.Time) TLSOption {
	return func(d *TLSConfig) {
		d.DialDeadline = t
	}
}

// WithConnTrace enables [Conn] trace logging to stdout.
func WithConnTrace() TLSOption {
	return func(d *TLSConfig) {
		d.TraceEnabled = true
	}
}
