package client

import (
	"fmt"
	"runtime"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

type SSL struct {
	ssl *libssl.SSL
}

// NewSSL creates an [SSL] object using [SSLContext]. [SSL] is used for creating
// a single TLS connection.
func NewSSL(sslCtx *SSLContext, c *Config) (*SSL, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	ssl, err := newSsl(sslCtx)
	if err != nil {
		libssl.SSLFree(ssl)
		return nil, err
	}
	s := &SSL{ssl: ssl}
	s.apply(c)
	runtime.SetFinalizer(s, nil)
	return s, nil
}

// Free will free up the [SSL] object and any resources it has allocated.
func (s *SSL) Free() {
	libssl.SSLFree(s.ssl)
}

func newSsl(sslCtx *SSLContext) (*libssl.SSL, error) {
	ssl, err := libssl.NewSSL(sslCtx.ctx)
	if err != nil {
		return nil, err
	}
	return ssl, nil
}

func (s *SSL) apply(c *Config) error {
	// Apply certificate verification flags
	var x509Flags int64
	if c.CertificateChecks&X509CheckTimeValidity != 0 {
		x509Flags |= libssl.X509_V_FLAG_USE_CHECK_TIME
	}
	if c.CertificateChecks&X509CheckCRL != 0 {
		x509Flags |= libssl.X509_V_FLAG_CRL_CHECK
	}
	if c.CertificateChecks&X509CheckCRLAll != 0 {
		x509Flags |= libssl.X509_V_FLAG_CRL_CHECK_ALL
	}
	if c.CertificateChecks&X509StrictMode != 0 {
		x509Flags |= libssl.X509_V_FLAG_X509_STRICT
	}
	if c.CertificateChecks&X509AllowPartialChains != 0 {
		x509Flags |= libssl.X509_V_FLAG_PARTIAL_CHAIN
	}
	if c.CertificateChecks&X509TrustedFirst != 0 {
		x509Flags |= libssl.X509_V_FLAG_TRUSTED_FIRST
	}

	verifyParam, err := libssl.SSLGet0Param(s.ssl)
	if err != nil {
		return err
	}
	if err := libssl.X509VerifyParamSetFlags(verifyParam, x509Flags); err != nil {
		return fmt.Errorf("failed to set verify flags: %w", err)
	}

	return nil
}
