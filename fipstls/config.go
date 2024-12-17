package fipstls

import (
	"path/filepath"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// TLS version constants.
type Version int

const (
	Version1  = libssl.TLS1_VERSION
	Version11 = libssl.TLS1_1_VERSION
	Version12 = libssl.TLS1_2_VERSION
	Version13 = libssl.TLS1_3_VERSION
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

type Config struct {
	// LibsslVersion is the libssl version to dynamically load.
	LibsslVersion string

	// CaFile is the path to a file of CA certificates in PEM format.
	CaFile string

	// CaPath is the path to a directory containing CA certificates in PEM format.
	CaPath string

	// MinTLSVersion is the minimum TLS version to accept.
	MinTLSVersion int64

	// MaxTLSVersion is the maximum TLS version to use.
	MaxTLSVersion int64

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
}

// DefaultConfig returns a [Config] with sane default options. The default context is uninitialized.
func NewDefaultConfig() *Config {
	return &Config{
		Method:            ClientMethod,
		MinTLSVersion:     Version12,
		VerifyMode:        VerifyPeer,
		CertificateChecks: X509CheckTimeValidity,
	}
}

// ConfigOption is a functional option for configuring [Config].
type ConfigOption func(*Config)

// NewConfig creates a new [Config] with the given options.
func NewConfig(opts ...ConfigOption) *Config {
	cfg := NewDefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithLibsslVersion sets the libssl version to dynamically load.
func WithLibsslVersion(version string) ConfigOption {
	return func(cfg *Config) {
		cfg.LibsslVersion = version
	}
}

// WithCaFile sets the path to a file of CA certificates in PEM format.
func WithCaFile(path string) ConfigOption {
	return func(cfg *Config) {
		cfg.CaPath = filepath.Dir(path)
		cfg.CaFile = path
	}
}

// WithMinTLSVersion sets the minimum TLS version to accept.
func WithMinTLSVersion(version int64) ConfigOption {
	return func(cfg *Config) {
		cfg.MinTLSVersion = version
	}
}

// WithMaxTLSVersion sets the maximum TLS version to use.
func WithMaxTLSVersion(version int64) ConfigOption {
	return func(cfg *Config) {
		cfg.MaxTLSVersion = version
	}
}

// WithMethod sets the TLS method to use.
func WithMethod(method Method) ConfigOption {
	return func(cfg *Config) {
		cfg.Method = method
	}
}

// WithVerifyMode sets the certificate verification mode.
func WithVerifyMode(mode VerifyMode) ConfigOption {
	return func(cfg *Config) {
		cfg.VerifyMode = mode
	}
}

// WithCertificateChecks sets the certificate verification flags.
func WithCertificateChecks(flags X509VerifyFlags) ConfigOption {
	return func(cfg *Config) {
		cfg.CertificateChecks = flags
	}
}

// WithSessionTicketsDisabled disables session ticket support.
func WithSessionTicketsDisabled() ConfigOption {
	return func(cfg *Config) {
		cfg.SessionTicketsDisabled = true
	}
}

// WithSessionCacheDisabled disables session caching.
func WithSessionCacheDisabled() ConfigOption {
	return func(cfg *Config) {
		cfg.SessionCacheDisabled = true
	}
}

// WithCompressionDisabled disables compression.
func WithCompressionDisabled() ConfigOption {
	return func(cfg *Config) {
		cfg.CompressionDisabled = true
	}
}

// WithRenegotiationDisabled disables all renegotiation.
func WithRenegotiationDisabled() ConfigOption {
	return func(cfg *Config) {
		cfg.RenegotiationDisabled = true
	}
}
