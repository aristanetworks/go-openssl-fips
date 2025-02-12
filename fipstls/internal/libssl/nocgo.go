//go:build !cgo

package libssl

import "errors"

// OpenSSL initialization options
const (
	OPENSSL_INIT_LOAD_CRYPTO_STRINGS = iota
	OPENSSL_INIT_ADD_ALL_CIPHERS     = iota
	OPENSSL_INIT_ADD_ALL_DIGESTS     = iota
	OPENSSL_INIT_LOAD_CONFIG         = iota
)

// SSL/TLS options
const (
	SSL_OP_NO_SSLv2                               = iota
	SSL_OP_NO_SSLv3                               = iota
	SSL_OP_NO_TLSv1                               = iota
	SSL_OP_NO_TLSv1_1                             = iota
	SSL_OP_NO_TLSv1_2                             = iota
	SSL_OP_NO_TLSv1_3                             = iota
	SSL_OP_ALL                                    = iota
	SSL_OP_NO_TICKET                              = iota
	SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = iota
	SSL_OP_NO_COMPRESSION                         = iota
	SSL_OP_CIPHER_SERVER_PREFERENCE               = iota
	SSL_OP_TLS_ROLLBACK_BUG                       = iota
)

// SSL verify modes
const (
	SSL_VERIFY_NONE                 = iota
	SSL_VERIFY_PEER                 = iota
	SSL_VERIFY_FAIL_IF_NO_PEER_CERT = iota
	SSL_VERIFY_CLIENT_ONCE          = iota
	SSL_VERIFY_POST_HANDSHAKE       = iota
)

// SSL_CTX_set_mode options
const (
	SSL_MODE_ENABLE_PARTIAL_WRITE       = iota
	SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = iota
	SSL_MODE_AUTO_RETRY                 = iota
	SSL_MODE_RELEASE_BUFFERS            = iota
)

// TLS version constants
const (
	TLS1_VERSION   = iota
	TLS1_1_VERSION = iota
	TLS1_2_VERSION = iota
	TLS1_3_VERSION = iota
)

// Error constants
const (
	SSL_ERROR_NONE             = iota
	SSL_ERROR_SSL              = iota
	SSL_ERROR_WANT_READ        = iota
	SSL_ERROR_WANT_WRITE       = iota
	SSL_ERROR_WANT_X509_LOOKUP = iota
	SSL_ERROR_SYSCALL          = iota
	SSL_ERROR_ZERO_RETURN      = iota
	SSL_ERROR_WANT_CONNECT     = iota
	SSL_ERROR_WANT_ACCEPT      = iota
)

// X509 verification flags
const (
	X509_V_FLAG_USE_CHECK_TIME       = iota
	X509_V_FLAG_CRL_CHECK            = iota
	X509_V_FLAG_CRL_CHECK_ALL        = iota
	X509_V_FLAG_IGNORE_CRITICAL      = iota
	X509_V_FLAG_X509_STRICT          = iota
	X509_V_FLAG_ALLOW_PROXY_CERTS    = iota
	X509_V_FLAG_POLICY_CHECK         = iota
	X509_V_FLAG_EXPLICIT_POLICY      = iota
	X509_V_FLAG_INHIBIT_ANY          = iota
	X509_V_FLAG_INHIBIT_MAP          = iota
	X509_V_FLAG_NOTIFY_POLICY        = iota
	X509_V_FLAG_EXTENDED_CRL_SUPPORT = iota
	X509_V_FLAG_USE_DELTAS           = iota
	X509_V_FLAG_CHECK_SS_SIGNATURE   = iota
	X509_V_FLAG_TRUSTED_FIRST        = iota
	X509_V_FLAG_SUITEB_128_LOS_ONLY  = iota
	X509_V_FLAG_SUITEB_192_LOS       = iota
	X509_V_FLAG_SUITEB_128_LOS       = iota
	X509_V_FLAG_PARTIAL_CHAIN        = iota
	X509_V_FLAG_NO_ALT_CHAINS        = iota
	X509_V_FLAG_NO_CHECK_TIME        = iota
)

// X509 verification constants
const (
	X509_V_OK                                     = iota
	X509_V_ERR_UNSPECIFIED                        = iota
	X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT          = iota
	X509_V_ERR_UNABLE_TO_GET_CRL                  = iota
	X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE   = iota
	X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE    = iota
	X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = iota
	X509_V_ERR_CERT_SIGNATURE_FAILURE             = iota
	X509_V_ERR_CRL_SIGNATURE_FAILURE              = iota
	X509_V_ERR_CERT_NOT_YET_VALID                 = iota
	X509_V_ERR_CERT_HAS_EXPIRED                   = iota
	X509_V_ERR_CRL_NOT_YET_VALID                  = iota
	X509_V_ERR_CRL_HAS_EXPIRED                    = iota
	X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD     = iota
	X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD      = iota
	X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD     = iota
	X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD     = iota
	X509_V_ERR_OUT_OF_MEM                         = iota
	X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT        = iota
	X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN          = iota
	X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY  = iota
	X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE    = iota
	X509_V_ERR_CERT_CHAIN_TOO_LONG                = iota
	X509_V_ERR_CERT_REVOKED                       = iota
	X509_V_ERR_NO_ISSUER_PUBLIC_KEY               = iota
	X509_V_ERR_PATH_LENGTH_EXCEEDED               = iota
	X509_V_ERR_INVALID_PURPOSE                    = iota
	X509_V_ERR_CERT_UNTRUSTED                     = iota
	X509_V_ERR_CERT_REJECTED                      = iota
)

// SSL and SSL_CTX ctrl constants
const (
	SSL_CTRL_OPTIONS               = iota
	SSL_CTRL_SET_TLSEXT_HOSTNAME   = iota
	SSL_CTRL_SET_MIN_PROTO_VERSION = iota
	SSL_CTRL_SET_MAX_PROTO_VERSION = iota
)

const (
	TLSEXT_NAMETYPE_host_name = iota
)

// SSL shutdown modes
const (
	SSL_NO_SHUTDOWN       = iota
	SSL_SENT_SHUTDOWN     = iota
	SSL_RECEIVED_SHUTDOWN = iota
)

// BIO lookup types
const (
	BIO_LOOKUP_CLIENT = iota
	BIO_LOOKUP_SERVER = iota
)

var ErrMethodUnimplemented = errors.New("method unimplemented")

type BIO struct{}
type SSLCtx struct{}
type SSL struct{}
type SSLMethod struct{}
type DebugMode int

const DebugDisabled DebugMode = iota

func BIOFree(bio *BIO) error                          { return ErrMethodUnimplemented }
func CheckLeaks()                                     {}
func CheckVersion(version string) (exists, fips bool) { return false, false }
func CreateBIO(hostname, port string, family, mode int) (*BIO, int, error) {
	return nil, 0, ErrMethodUnimplemented
}
func EnableDebugLogging()                                       {}
func FIPS() bool                                                { return false }
func GetVersion() string                                        { return "" }
func Init(file string) error                                    { return ErrMethodUnimplemented }
func NewOpenSSLError(msg string) error                          { return ErrMethodUnimplemented }
func NewSSL(sslCtx *SSLCtx) (*SSL, error)                       { return nil, ErrMethodUnimplemented }
func NewSSLCtx(tlsMethod *SSLMethod) (*SSLCtx, error)           { return nil, ErrMethodUnimplemented }
func NewTLSClientMethod() (*SSLMethod, error)                   { return nil, ErrMethodUnimplemented }
func NewTLSMethod() (*SSLMethod, error)                         { return nil, ErrMethodUnimplemented }
func NewTLSServerMethod() (*SSLMethod, error)                   { return nil, ErrMethodUnimplemented }
func Reset()                                                    {}
func SSLClearError()                                            {}
func SSLConfigureBIO(ssl *SSL, bio *BIO, hostname string) error { return ErrMethodUnimplemented }
func SSLConnect(ssl *SSL) error                                 { return ErrMethodUnimplemented }
func SSLCtxConfigure(ctx *SSLCtx, config *CtxConfig) error      { return ErrMethodUnimplemented }
func SSLCtxFree(sslCtx *SSLCtx) error                           { return ErrMethodUnimplemented }
func SSLCtxSetH2Proto(sslCtx *SSLCtx) error                     { return ErrMethodUnimplemented }
func SSLFree(ssl *SSL) error                                    { return ErrMethodUnimplemented }
func SSLGetError(ssl *SSL, ret int) int                         { return 0 }
func SSLGetShutdown(ssl *SSL) int                               { return 0 }
func SSLGetVerifyResult(ssl *SSL) error                         { return ErrMethodUnimplemented }
func SSLReadEx(ssl *SSL, size int64) ([]byte, int, error)       { return nil, 0, ErrMethodUnimplemented }
func SSLSetShutdown(ssl *SSL, mode int) error                   { return ErrMethodUnimplemented }
func SSLShutdown(ssl *SSL) error                                { return ErrMethodUnimplemented }
func SSLStatusALPN(ssl *SSL) string                             { return "" }
func SSLWriteEx(ssl *SSL, req []byte) (int, error)              { return 0, ErrMethodUnimplemented }
func SetFIPS(enabled bool) error                                { return ErrMethodUnimplemented }
func VersionText() string                                       { return "" }
func X509VerifyCertErrorString(n int64) string                  { return "" }
