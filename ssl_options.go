package ossl

import "path/filepath"

type ConfigOption func(*Config)

// WithCaFile sets the CA file path.
func WithCaFile(caFile string) ConfigOption {
	return func(c *Config) {
		c.CaFile = caFile
		c.CaPath = filepath.Dir(caFile)
	}
}

// WithMinVersion sets the minimum TLS version.
func WithMinVersion(version int64) ConfigOption {
	return func(c *Config) {
		c.MinVersion = version
	}
}

// WithMaxVersion sets the maximum TLS version.
func WithMaxVersion(version int64) ConfigOption {
	return func(c *Config) {
		c.MaxVersion = version
	}
}

// WithTLSMethod sets the TLS method.
func WithTLSMethod(method Method) ConfigOption {
	return func(c *Config) {
		c.TLSMethod = method
	}
}

// WithVerifyMode sets the certificate verification mode.
func WithVerifyMode(mode VerifyMode) ConfigOption {
	return func(c *Config) {
		c.VerifyMode = mode
	}
}

// WithCertificateChecks sets the certificate verification flags.
func WithCertificateChecks(checks X509VerifyFlags) ConfigOption {
	return func(c *Config) {
		c.CertificateChecks = checks
	}
}

// WithSessionTicketsDisabled disables session ticket support.
func WithSessionTicketsDisabled() ConfigOption {
	return func(c *Config) {
		c.SessionTicketsDisabled = true
	}
}

// WithSessionCacheDisabled disables session caching.
func WithSessionCacheDisabled() ConfigOption {
	return func(c *Config) {
		c.SessionCacheDisabled = true
	}
}

// WithRenegotiationDisabled disables renegotiation.
func WithRenegotiationDisabled() ConfigOption {
	return func(c *Config) {
		c.RenegotiationDisabled = true
	}
}

// WithCompressionDisabled disables TLS compression.
func WithCompressionDisabled() ConfigOption {
	return func(c *Config) {
		c.CompressionDisabled = true
	}
}

// WithLibsslVersion will dynamically load the libssl version.
func WithLibsslVersion(version string) ConfigOption {
	return func(c *Config) {
		c.LibsslVersion = version
	}
}

// WithConnTraceEnabled will enable trace logging to stdout in the underlying [Conn].
func WithConnTraceEnabled() ConfigOption {
	return func(c *Config) {
		c.ConnTraceEnabled = true
	}
}
