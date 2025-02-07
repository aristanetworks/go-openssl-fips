package fipstls

import (
	"errors"
	"path/filepath"
	"slices"

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
	if err := libssl.Init(version); err != nil {
		return errors.Join(ErrLoadLibSslFailed, err)
	}
	libsslInit = true
	return nil
}

// Context is used for configuring and creating SSL [Conn] connections.
type Context struct {
	ctx    *libssl.SSLCtx
	closer Closer
	unsafe bool
	TLS    *Config
}

// NewCtx configures the [Context] and allocates a C.SSL_CTX object.
//
// The C.SSL_CTX will be freed on [Conn.Close].
func NewCtx(tls *Config) (*Context, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	ctx := &Context{TLS: tls, closer: noopCloser{}}
	if ctx.TLS == nil {
		ctx.TLS = NewDefaultConfig()
	}
	if err := ctx.new(); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (c *Context) new() error {
	method, err := libssl.NewTLSClientMethod()
	if err != nil {
		return err
	}
	ctx, err := libssl.NewSSLCtx(method)
	if err != nil {
		libssl.SSLCtxFree(ctx)
		return err
	}
	if err = c.apply(ctx); err != nil {
		libssl.SSLCtxFree(ctx)
		return err
	}
	c.ctx = ctx
	c.closer = newOnceCloser(func() error {
		return libssl.SSLCtxFree(c.ctx)
	})
	return nil
}

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

	// Set verification mode to peer as default, using VerifyNone as the zero-value
	if c.TLS.VerifyMode == verifyNone {
		c.TLS.VerifyMode = VerifyPeer
	}
	// Only set VerifyNone if insecure is set
	if c.TLS.InsecureSkipVerify {
		c.TLS.VerifyMode = verifyNone
	}
	var verifyMode int
	switch c.TLS.VerifyMode {
	case verifyNone:
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

	// Set h2 proto for HTTP/2 clients
	var proto string
	if slices.Contains(c.TLS.NextProtos, "h2") {
		proto = "h2"
	}

	if c.TLS.CaFile != "" && c.TLS.CaPath == "" {
		c.TLS.CaPath = filepath.Dir(c.TLS.CaFile)
	}

	return libssl.SSLCtxConfigure(ctx, &libssl.CtxConfig{
		MinTLS:     c.TLS.MinTLSVersion,
		MaxTLS:     c.TLS.MaxTLSVersion,
		Options:    options,
		VerifyMode: verifyMode,
		NextProto:  proto,
		CaFile:     c.TLS.CaFile,
		CaPath:     c.TLS.CaPath,
		CertFile:   c.TLS.CertFile,
		KeyFile:    c.TLS.KeyFile,
	})
}

// Ctx returns a pointer to the underlying C.SSL_CTX C object.
func (c *Context) Ctx() *libssl.SSLCtx {
	return c.ctx
}

// Close frees the C.SSL_CTX C object allocated for [Context].
func (c *Context) Close() error {
	return c.closer.Close()
}
