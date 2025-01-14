package fipstls

import (
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

	// CaFile is the path to the CA certificates bundle in PEM format.
	CaFile string

	// CaPath is the path to a directory containing CA certificates in PEM format.
	CaPath string

	// CertFile is the path to the client certificate bundle in PEM format.
	CertFile string

	// KeyFile is the path to the client private key in PEM format.
	KeyFile string

	// InsecureSkipVerify will skip host verification.
	InsecureSkipVerify bool

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

	// CompressionDisabled disables compression.
	CompressionDisabled bool

	// RenegotiationDisabled disables all renegotiation.
	RenegotiationDisabled bool

	// NextProtos are the ALPN protocol to prefer when establishing a connection.
	NextProtos []string
}

// DefaultConfig returns a [Config] with sane default options.
func NewDefaultConfig() *Config {
	return &Config{
		Method:            ClientMethod,
		MinTLSVersion:     Version12,
		VerifyMode:        VerifyPeer,
		CertificateChecks: X509CheckTimeValidity,
	}
}
