package ossl

import (
	"fmt"
	"sync"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// SSLContext stores configuration options used to create [SSL] connections.
type SSLContext struct {
	ctx       *libssl.SSLCtx
	closeOnce sync.Once
	closeErr  error
}

// NewSSLContext creates a new [SSLContext] using the supplied [Config].
func NewSSLContext(c *Config) (*SSLContext, error) {
	if err := Init(c.LibsslVersion); err != nil {
		return nil, err
	}
	var sslCtx *SSLContext
	if err := runWithLockedOSThread(func() error {
		ctx, err := newSslCtx(c.TLSMethod)
		if err != nil {
			libssl.SSLCtxFree(ctx)
			return err
		}
		sslCtx = &SSLContext{ctx: ctx}
		if err := sslCtx.apply(c); err != nil {
			libssl.SSLCtxFree(ctx)
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return sslCtx, nil
}

// Close will free the C memory allocated by [SSLContext]. [SSLContext] should not be used after
// calling free.
func (c *SSLContext) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = libssl.SSLCtxFree(c.ctx)
	})
	return c.closeErr
}

// newSslCtx creates a new [libssl.SSLCtx] object from the TLS [Method].
func newSslCtx(m Method) (*libssl.SSLCtx, error) {
	var method *libssl.SSLMethod
	var err error
	switch m {
	case ClientMethod:
		method, err = libssl.NewTLSClientMethod()
	case ServerMethod:
		method, err = libssl.NewTLSServerMethod()
	case DefaultMethod:
		method, err = libssl.NewTLSMethod()
	}
	if err != nil {
		return nil, err
	}
	sslCtx, err := libssl.NewSSLCtx(method)
	if err != nil {
		return nil, err
	}
	return sslCtx, nil
}

// apply applies the security options to an SSL context
func (s *SSLContext) apply(c *Config) error {
	var options int64

	// Apply feature-specific options
	if c.SessionTicketsDisabled {
		options |= libssl.SSL_OP_NO_TICKET
	}
	if c.RenegotiationDisabled {
		options |= libssl.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	}
	if c.TLSCompressionDisabled {
		options |= libssl.SSL_OP_NO_COMPRESSION
	}

	if err := libssl.SSLCtxSetOptions(s.ctx, options); err != nil {
		return fmt.Errorf("failed to set SSL_CTX options: %w", err)
	}

	// Set verification mode
	var verifyMode int
	switch c.VerifyMode {
	case VerifyNone:
		verifyMode = libssl.SSL_VERIFY_NONE
	case VerifyPeer:
		verifyMode = libssl.SSL_VERIFY_PEER
	case VerifyFailIfNoPeerCert:
		verifyMode = libssl.SSL_VERIFY_PEER | libssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	case VerifyClientOnce:
		verifyMode = libssl.SSL_VERIFY_PEER | libssl.SSL_VERIFY_CLIENT_ONCE
	case VerifyPostHandshake:
		verifyMode = libssl.SSL_VERIFY_PEER | libssl.SSL_VERIFY_POST_HANDSHAKE
	}

	libssl.SSLCtxSetVerify(s.ctx, verifyMode, libssl.SSLVerifyCallback{})

	// Set protocol versions
	if c.MinVersion != 0 {
		if err := libssl.SSLCtxSetMinProtoVersion(s.ctx, c.MinVersion); err != nil {
			return fmt.Errorf("failed to set minimum protocol version: %w", err)
		}
	}
	if c.MaxVersion != 0 {
		if err := libssl.SSLCtxSetMaxProtoVersion(s.ctx, c.MaxVersion); err != nil {
			return fmt.Errorf("failed to set maximum protocol version: %w", err)
		}
	}

	if c.CaFile == "" || c.CaPath == "" {
		// Use the default trusted certificate store
		if err := libssl.SSLCtxSetDefaultVerifyPaths(s.ctx); err != nil {
			return err
		}
	} else {
		// Use specified trusted certificate store
		if err := libssl.SSLCtxLoadVerifyLocations(s.ctx, c.CaFile, c.CaPath); err != nil {
			return err
		}
	}
	return nil
}
