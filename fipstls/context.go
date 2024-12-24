package fipstls

import (
	"errors"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

var (
	libsslInit bool
)

// Init should be called before any calls into libssl. If the version string is empty, it will pick
// the highest libssl.so version automatically.
func Init(version string) error {
	if libsslInit {
		return nil
	}
	if version == "" {
		version = libssl.GetVersion()
	}
	if err := libssl.Init(version); err != nil {
		return errors.Join(ErrLoadLibSslFailed, err)
	}
	libsslInit = true
	return nil
}

// Context wraps the C.SSL_CTX and stores [Config] options used to create
// [Conn] connections.
type Context struct {
	ctx    *libssl.SSLCtx
	closer Closer
	unsafe bool
	TLS    *Config
}

// NewCtx configures the [Context] but will not allocate a C.SSL_CTX object.
//
// Calling [Context.New] will create an SSLContext with a C.SSL_CTX allocated
// using the [Context.TLS] options.
//
// The C.SSL_CTX will be freed on [Context.Close].
func NewCtx(opts ...ConfigOption) *Context {
	return &Context{
		closer: noopCloser{},
		TLS:    NewConfig(opts...),
	}
}

// NewUnsafeCtx configures and allocates a C.SSL_CTX object that will be reused
// in creating [Conn] connections. The caller is responsible for freeing the
// C memory allocated for C.SSL_CTX with [Context.Close].
//
// Calling [Context.New] will create an SSLContext that references the
// pointer receiver's C.SSL_CTX, but can't free it.
func NewUnsafeCtx(opts ...ConfigOption) (ctx *Context, err error) {
	ctx = NewCtx(opts...)
	ctx.unsafe = true
	if !ctx.unsafe {
		return ctx, nil
	}
	if err = ctx.addCloser(ctx); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (c *Context) new() (ctx *libssl.SSLCtx, err error) {
	if err = Init(c.TLS.LibsslVersion); err != nil {
		return nil, err
	}
	ctx, err = newSslCtx(c.TLS.Method)
	if err != nil {
		return nil, err
	}
	if err = c.apply(ctx); err != nil {
		return nil, err
	}
	return ctx, nil
}

// newSslCtx creates a new C.SSL_CTX object from the TLS [Method].
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
		return err
	}
	if c.TLS.NextProto == ALPNProtoH2Only {
		if err := libssl.SSLCtxSetH2Proto(ctx); err != nil {
			return err
		}
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
	if c.TLS.MinTLSVersion != 0 {
		if err := libssl.SSLCtxSetMinProtoVersion(ctx, c.TLS.MinTLSVersion); err != nil {
			return err
		}
	}
	if c.TLS.MaxTLSVersion != 0 {
		if err := libssl.SSLCtxSetMaxProtoVersion(ctx, c.TLS.MaxTLSVersion); err != nil {
			return err
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

// Ctx returns a pointer to the underlying C.SSL_CTX C object.
func (c *Context) Ctx() *libssl.SSLCtx {
	return c.ctx
}

// Close frees the C.SSL_CTX C object allocated for [Context].
func (c *Context) Close() error {
	return c.closer.Close()
}

// addCloser will create a new C.SSL_CTX and add a closer to free it.
func (c *Context) addCloser(cc *Context) (err error) {
	cc.ctx, err = c.new()
	if err != nil {
		return err
	}
	cc.closer = newOnceCloser(func() error {
		return libssl.SSLCtxFree(cc.ctx)
	})
	return nil
}

// New returns a new Context derived from this [Context]. It either references
// the C.SSL_CTX or creates a new one from the [Config].
func (c *Context) New() (ctx *Context, err error) {
	ctx = &Context{ctx: c.ctx, TLS: c.TLS, closer: &noopCloser{}}
	if !c.unsafe {
		// [Conn.Close] will free the memory
		if err = c.addCloser(ctx); err != nil {
			return ctx, err
		}
	}
	return ctx, nil
}
