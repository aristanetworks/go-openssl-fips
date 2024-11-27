package ossl

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

type SSLContext struct {
	ctx      *libssl.SSLCtx
	freeOnce sync.Once
	freeErr  error
}

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
		runtime.SetFinalizer(sslCtx, nil)
		return nil
	}); err != nil {
		return nil, err
	}
	return sslCtx, nil
}

func (c *SSLContext) Free() error {
	c.freeOnce.Do(func() {
		c.freeErr = libssl.SSLCtxFree(c.ctx)
	})
	return c.freeErr
}

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
	if c.CompressionDisabled {
		options |= libssl.SSL_OP_NO_COMPRESSION
	}

	if err := libssl.SSLCtxSetOptions(s.ctx, options); err != nil {
		return fmt.Errorf("failed to set SSL_CTX options: %w", err)
	}

	// libssl.SSLCtxSetReadAhead(s.ctx, 1)
	// For non-blocking IO
	// options = 0
	// options |= libssl.SSL_MODE_ENABLE_PARTIAL_WRITE
	// options |= libssl.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
	// options |= libssl.SSL_MODE_AUTO_RETRY
	// if err := libssl.SSLCtxSetMode(s.ctx, options); err != nil {
	// 	return fmt.Errorf("failed to set SSL_CTX mode: %w", err)
	// }

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
