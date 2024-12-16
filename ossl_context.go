package ossl

import (
	"fmt"
	"io"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// Context stores configuration options used to create [SSL] connections.
type Context struct {
	ctx    *libssl.SSLCtx
	closer io.Closer
	cached bool
	TLS    *TLSConfig
}

func NewDefaultTLSContext(opts ...TLSOption) *Context {
	tls := NewTLS()
	for _, o := range opts {
		o(tls)
	}
	return &Context{
		closer: noopCloser{},
		TLS:    tls,
	}
}

// NewContext creates a new [Context] using the supplied [Config].
func NewContext(opts ...TLSOption) (ctx *Context, err error) {
	ctx = &Context{}
	ctx.cached = ctx.TLS.CachedContext
	if ctx.cached {
		if err = ctx.makeCloseable(ctx); err != nil {
			return nil, err
		}
	}
	return ctx, nil
}

func (c *Context) new() (ctx *libssl.SSLCtx, err error) {
	if err = Init(c.TLS.LibsslVersion); err != nil {
		return nil, err
	}
	if err = runWithLockedOSThread(func() error {
		ctx, err = newSslCtx(c.TLS.Method)
		if err != nil {
			libssl.SSLCtxFree(ctx)
			return err
		}
		if err = c.apply(ctx); err != nil {
			libssl.SSLCtxFree(ctx)
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ctx, nil
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
func (c *Context) apply(ctx *libssl.SSLCtx) error {
	var options int64

	// Apply feature-specific options
	if c.TLS.SessionTicketsDisabled {
		options |= libssl.SSL_OP_NO_TICKET
	}
	if c.TLS.RenegotiationDisabled {
		options |= libssl.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	}
	if c.TLS.CompressionDisabled {
		options |= libssl.SSL_OP_NO_COMPRESSION
	}

	if err := libssl.SSLCtxSetOptions(ctx, options); err != nil {
		return fmt.Errorf("failed to set SSL_CTX options: %w", err)
	}

	// Set verification mode
	var verifyMode int
	switch c.TLS.VerifyMode {
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

	libssl.SSLCtxSetVerify(ctx, verifyMode, libssl.SSLVerifyCallback{})

	// Set protocol versions
	if c.TLS.MinVersion != 0 {
		if err := libssl.SSLCtxSetMinProtoVersion(ctx, c.TLS.MinVersion); err != nil {
			return fmt.Errorf("failed to set minimum protocol version: %w", err)
		}
	}
	if c.TLS.MaxVersion != 0 {
		if err := libssl.SSLCtxSetMaxProtoVersion(ctx, c.TLS.MaxVersion); err != nil {
			return fmt.Errorf("failed to set maximum protocol version: %w", err)
		}
	}

	if c.TLS.CaFile == "" || c.TLS.CaPath == "" {
		// Use the default trusted certificate store
		if err := libssl.SSLCtxSetDefaultVerifyPaths(ctx); err != nil {
			return err
		}
	} else {
		// Use specified trusted certificate store
		if err := libssl.SSLCtxLoadVerifyLocations(ctx, c.TLS.CaFile, c.TLS.CaPath); err != nil {
			return err
		}
	}
	return nil
}

func (c *Context) Ctx() *libssl.SSLCtx {
	return c.ctx
}

// Close frees the [libssl.SSLCtx] C object allocated by [Context].
func (c *Context) Close() error {
	return c.closer.Close()
}

func (c *Context) makeCloseable(cc *Context) (err error) {
	cc.ctx, err = c.new()
	if err != nil {
		return err
	}
	cc.closer = &onceCloser{
		closeFunc: func() error {
			return libssl.SSLCtxFree(cc.ctx)
		},
	}
	return nil
}

// NewCtx returns a new Context derived from this [Context]. It either references
// this context or creates one from [Context.TLS] configuration.
func (c *Context) NewCtx() (ctx *Context, err error) {
	ctx = &Context{ctx: c.ctx, TLS: c.TLS, closer: &noopCloser{}}
	if !c.cached {
		if err = c.makeCloseable(ctx); err != nil {
			return nil, err
		}
	}
	return ctx, nil
}
