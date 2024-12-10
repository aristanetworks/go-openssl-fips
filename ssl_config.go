package ossl

import (
	"time"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

// Method represents TLS method modes
type Method int

const (
	DefaultMethod Method = iota

	ClientMethod

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

// X509VerifyFlags represents certificate verification flags
type X509VerifyFlags uint32

const (
	X509CheckTimeValidity  X509VerifyFlags = 1 << iota // Check certificate time validity
	X509CheckCRL                                       // Check certificate revocation
	X509CheckCRLAll                                    // Check entire certificate chain for revocation
	X509StrictMode                                     // Enable strict certificate checking
	X509AllowPartialChains                             // Allow partial certificate chains
	X509TrustedFirst                                   // Prefer trusted certificates when building chain
)

type Config struct {
	// LibsslVersion is the libssl version to dynamically load
	LibsslVersion string

	// CaFile is the path to a file of CA certificates in PEM format.
	CaFile string

	// CaPath is the path to a directory containing CA certificates in PEM format.
	CaPath string

	// MinVersion is the minimum TLS version to accept
	MinVersion int64

	// MaxVersion is the maximum TLS version to use
	MaxVersion int64

	// TLSMethod is the TLS method to use
	TLSMethod Method

	// VerifyMode controls how peer certificates are verified
	VerifyMode VerifyMode

	// CertificateChecks controls X.509 certificate verification
	CertificateChecks X509VerifyFlags

	// SessionTicketsDisabled disables session ticket support
	SessionTicketsDisabled bool

	// SessionCacheDisabled disables session caching
	SessionCacheDisabled bool

	// RenegotiationDisabled disables all renegotiation
	RenegotiationDisabled bool

	// CompressionDisabled disables TLS compression
	CompressionDisabled bool

	// Timeout is connection timeout
	Timeout time.Duration

	// ConnTraceEnabled
	ConnTraceEnabled bool
}

func DefaultConfig() *Config {
	return &Config{
		TLSMethod:         ClientMethod,
		MinVersion:        libssl.TLS1_2_VERSION,
		VerifyMode:        VerifyPeer,
		CertificateChecks: X509CheckTimeValidity,
		Timeout:           30 * time.Second,
	}
}
