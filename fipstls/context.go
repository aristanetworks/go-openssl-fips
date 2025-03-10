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

// Version returns the dynamically loaded libssl.so version, or an empty string otherwise.
func Version() string {
	if !libsslInit {
		return ""
	}
	return libssl.VersionText()
}

// FIPSMode returns true if FIPS mode is enabled in the dynamically loaded libssl.so, and false
// otherwise.
func FIPSMode() bool {
	if !libsslInit {
		return false
	}
	return libssl.FIPS()
}

// SetFIPS can be used to enable FIPS mode in the dynamically loaded libssl.so.
func SetFIPS(enabled bool) error {
	if !libsslInit {
		return ErrLoadLibSslFailed
	}
	return libssl.SetFIPS(enabled)
}

// Context is used for configuring and creating SSL [Conn] connections.
type Context struct {
	ctx    *libssl.SSLCtx
	closer Closer
}

// NewCtx configures the [Context] and allocates a C.SSL_CTX object.
//
// The C.SSL_CTX will be freed on [Conn.Close].
func NewCtx(tls *Config) (*Context, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	if tls == nil {
		tls = newDefaultConfig()
	}
	ctx := &Context{closer: noopCloser{}}
	if err := ctx.new(tls); err != nil {
		return ctx, err
	}
	return ctx, nil
}

func (c *Context) new(tls *Config) error {
	method, err := libssl.NewTLSClientMethod()
	if err != nil {
		return err
	}
	ctx, err := libssl.NewSSLCtx(method)
	if err != nil {
		libssl.SSLCtxFree(ctx)
		return err
	}
	if err := libssl.SSLCtxConfigure(ctx, newCtxConfig(tls)); err != nil {
		libssl.SSLCtxFree(ctx)
		return err
	}
	c.ctx = ctx
	c.closer = newOnceCloser(func() error {
		return libssl.SSLCtxFree(c.ctx)
	})
	return nil
}

// newCtxConfig creates the configuration that will be understood by the libssl SSLCtx APIs.
func newCtxConfig(tls *Config) *libssl.CtxConfig {
	// Copy common configuration options
	ctxConfig := &libssl.CtxConfig{
		MinTLS:   tls.MinTLSVersion,
		MaxTLS:   tls.MaxTLSVersion,
		CaFile:   tls.CaFile,
		CaPath:   tls.CaPath,
		CertFile: tls.CertFile,
		KeyFile:  tls.KeyFile,
	}
	// Set path to CaFile if present
	if tls.CaFile != "" && tls.CaPath == "" {
		ctxConfig.CaPath = filepath.Dir(tls.CaFile)
	}
	// Set h2 proto for HTTP/2 clients
	if slices.Contains(tls.NextProtos, "h2") {
		ctxConfig.NextProto = "h2"
	}
	// Apply feature-specific options
	if tls.SessionTicketsDisabled {
		ctxConfig.Options |= libssl.SSL_OP_NO_TICKET
	}
	if tls.RenegotiationDisabled {
		ctxConfig.Options |= libssl.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	}
	if tls.CompressionDisabled {
		ctxConfig.Options |= libssl.SSL_OP_NO_COMPRESSION
	}
	// Set verification mode to peer as default, using VerifyNone as the zero-value
	verifyMode := tls.VerifyMode
	if verifyMode == verifyNone {
		verifyMode = VerifyPeer
	}
	// Only set VerifyNone if insecure is set
	if tls.InsecureSkipVerify {
		verifyMode = verifyNone
	}
	switch verifyMode {
	case verifyNone:
		ctxConfig.VerifyMode = libssl.SSL_VERIFY_NONE
	case VerifyPeer:
		ctxConfig.VerifyMode = libssl.SSL_VERIFY_PEER
	case VerifyFailIfNoPeerCert:
		ctxConfig.VerifyMode = libssl.SSL_VERIFY_PEER | libssl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	case VerifyClientOnce:
		ctxConfig.VerifyMode = libssl.SSL_VERIFY_PEER | libssl.SSL_VERIFY_CLIENT_ONCE
	case VerifyPostHandshake:
		ctxConfig.VerifyMode = libssl.SSL_VERIFY_PEER | libssl.SSL_VERIFY_POST_HANDSHAKE
	}
	return ctxConfig
}

// Ctx returns a pointer to the underlying C.SSL_CTX C object.
func (c *Context) Ctx() *libssl.SSLCtx {
	return c.ctx
}

// Close frees the C.SSL_CTX C object allocated for [Context].
func (c *Context) Close() error {
	return c.closer.Close()
}
