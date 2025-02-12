package libssl

// #include "golibssl.h"
import "C"
import (
	"fmt"
	"unsafe"
)

type DebugMode int

const (
	DebugDisabled DebugMode = iota
	DebugEnabled
)

var debugLogging DebugMode

// EnableDebugLogging is used for enabling debug logging to stdout in C helper functions.
func EnableDebugLogging() {
	debugLogging = DebugEnabled
}

type SSLMethod struct {
	inner C.GO_SSL_METHOD_PTR
}

func NewTLSMethod() (*SSLMethod, error) {
	r := C.go_openssl_TLS_method()
	if r == nil {
		return nil, NewOpenSSLError("libssl: TLS_method")
	}
	return &SSLMethod{inner: r}, nil
}

func NewTLSClientMethod() (*SSLMethod, error) {
	r := C.go_openssl_TLS_client_method()
	if r == nil {
		return nil, NewOpenSSLError("libssl: TLS_client_method")
	}
	return &SSLMethod{inner: r}, nil
}

func NewTLSServerMethod() (*SSLMethod, error) {
	r := C.go_openssl_TLS_server_method()
	if r == nil {
		return nil, NewOpenSSLError("libssl: TLS_server_method")
	}
	return &SSLMethod{inner: r}, nil
}

// SSLCtx uses a TLS method to configure an SSL connection. It initializes the list of ciphers, the
// session cache setting, the callbacks, the keys and certificates and the options to their default
// values.
//
// SSL_CTX is a "factory" for creating SSL objects. You can create a single SSL_CTX object and
// then create multiple connections (i.e. SSL objects) from it. Note that internally to OpenSSL
// various items that are shared between multiple SSL objects are cached in the SSL_CTX for
// performance reasons. Therefore it is considered best practice to create one SSL_CTX for use by
// multiple SSL objects instead of having one SSL_CTX for each SSL object that you create.
type SSLCtx struct {
	inner C.GO_SSL_CTX_PTR
}

func NewSSLCtx(tlsMethod *SSLMethod) (*SSLCtx, error) {
	if tlsMethod == nil {
		return nil, NewOpenSSLError("libssl: SSL_CTX_new: SSL_method is nil")
	}
	r := C.go_openssl_SSL_CTX_new(tlsMethod.inner)
	if r == nil {
		return nil, NewOpenSSLError("libssl: SSL_CTX_new")
	}
	return &SSLCtx{inner: r}, nil
}

func SSLCtxSetH2Proto(sslCtx *SSLCtx) error {
	if r := C.go_openssl_set_h2_alpn(sslCtx.inner, C.int(int(debugLogging))); r != 0 {
		return NewOpenSSLError("libssl: SSL_CTX_set_alpn_protos: could not set H2 protocol")
	}
	return nil
}

func SSLStatusALPN(ssl *SSL) string {
	var proto [256]C.char
	var length C.int

	ret := C.go_openssl_check_alpn_status(ssl.inner, &proto[0], &length, C.int(int(debugLogging)))
	if ret == 0 {
		return "no protocol selected"
	}
	return string(C.GoBytes(unsafe.Pointer(&proto[0]), length))
}

func SSLCtxFree(sslCtx *SSLCtx) error {
	if sslCtx == nil {
		return NewOpenSSLError("libssl: SSL_CTX_free: SSL_CTX is nil")
	}
	C.go_openssl_SSL_CTX_free(sslCtx.inner)
	return nil
}

func SSLCtxConfigure(ctx *SSLCtx, config *CtxConfig) error {
	cNextProto := C.CString(config.NextProto)
	cCaPath := C.CString(config.CaPath)
	cCaFile := C.CString(config.CaFile)
	cCertFile := C.CString(config.CertFile)
	cKeyFile := C.CString(config.KeyFile)
	defer C.free(unsafe.Pointer(cNextProto))
	defer C.free(unsafe.Pointer(cCaPath))
	defer C.free(unsafe.Pointer(cCaFile))
	defer C.free(unsafe.Pointer(cCertFile))
	defer C.free(unsafe.Pointer(cKeyFile))
	if r := C.go_openssl_ctx_configure(ctx.inner, C.long(config.MinTLS), C.long(config.MaxTLS),
		C.long(config.Options), C.int(config.VerifyMode), cNextProto, cCaPath, cCaFile, cCertFile,
		cKeyFile, C.int(int(debugLogging)),
	); r != 0 {
		return NewOpenSSLError("libssl: ctx_configure failed")
	}
	return nil
}

// SSL holds data for a TLS connection. It inherits the settings of the underlying context ctx:
// connection method, options, verification settings, timeout settings.
type SSL struct {
	inner C.GO_SSL_PTR
}

func NewSSL(sslCtx *SSLCtx) (*SSL, error) {
	if sslCtx == nil {
		return nil, NewOpenSSLError("libssl: SSL_new: SSL_CTX is nil")
	}
	r := C.go_openssl_SSL_new(sslCtx.inner)
	if r == nil {
		return nil, NewOpenSSLError("libssl: SSL_new")
	}
	return &SSL{inner: r}, nil
}

func SSLFree(ssl *SSL) error {
	if ssl == nil {
		return NewOpenSSLError("libssl: SSL_clear: SSL is nil")
	}
	C.go_openssl_SSL_free(ssl.inner)
	return nil
}

func SSLConnect(ssl *SSL) error {
	if ssl == nil {
		return NewOpenSSLError("libssl: SSL_connect: SSL is nil")
	}
	if r := C.go_openssl_SSL_connect(ssl.inner); r != 1 {
		return newSSLError("libssl: SSL_connect", SSLGetError(ssl, int(r)))
	}
	return nil
}

// SSLShutdown closes an active TLS/SSL connection. It sends the "close notify" shutdown alert to
// the peer.
func SSLShutdown(ssl *SSL) error {
	if ssl == nil {
		return NewOpenSSLError("libssl: SSL_shutdown: SSL is nil")
	}
	r := int(C.go_openssl_SSL_shutdown(ssl.inner))
	switch r {
	case 1:
		return nil
	case 0:
		// Bidirectional shutdown must be performed. SSL_shutdown will need to be called again.
		if r := int(C.go_openssl_SSL_shutdown(ssl.inner)); r < 0 {
			return newSSLError("libssl: SSL_shutdown", SSLGetError(ssl, r))
		}
		return nil
	default:
		return newSSLError("libssl: SSL_shutdown", SSLGetError(ssl, r))
	}
}

// SSLGetShutdown returns the shutdown mode of [Conn].
func SSLGetShutdown(ssl *SSL) int {
	if ssl == nil {
		return C.GO_SSL_RECEIVED_SHUTDOWN
	}
	return int(C.go_openssl_SSL_get_shutdown(ssl.inner))
}

// SSLSetShutdown sets the shutdown state of [Conn] to mode.
func SSLSetShutdown(ssl *SSL, mode int) error {
	if ssl == nil {
		return NewOpenSSLError("libssl: SSL_set_shutdown: SSL is nil")
	}
	C.go_openssl_SSL_set_shutdown(ssl.inner, C.int(mode))
	return nil
}

func SSLWriteEx(ssl *SSL, req []byte) (int, error) {
	if ssl == nil {
		return 0, NewOpenSSLError("libssl: SSL_write_ex: SSL is nil")
	}
	cBytes := C.CBytes(req)
	defer C.free(cBytes)
	var written C.size_t
	r := C.go_openssl_SSL_write_ex(
		ssl.inner,
		cBytes,
		C.size_t(len(req)),
		&written)
	if r != 1 {
		return 0, newSSLError("libssl: SSL_write_ex", SSLGetError(ssl, int(r)))
	}
	return int(written), nil
}

func SSLReadEx(ssl *SSL, size int64) ([]byte, int, error) {
	if ssl == nil {
		return nil, 0, NewOpenSSLError("libssl: SSL_read_ex: SSL is nil")
	}
	cBuf := C.malloc(C.size_t(size))
	defer C.free(cBuf)
	var readBytes C.size_t
	r := C.go_openssl_SSL_read_ex(
		ssl.inner,
		cBuf,
		C.size_t(size),
		&readBytes)
	if r != 1 {
		return nil, 0, newSSLError("libssl: SSL_read_ex", SSLGetError(ssl, int(r)))
	}
	return C.GoBytes(cBuf, C.int(readBytes)), int(readBytes), nil
}

func SSLGetVerifyResult(ssl *SSL) error {
	if ssl == nil {
		return NewOpenSSLError("libssl: SSL_get_verify_result: SSL is nil")
	}
	res := int64(C.go_openssl_SSL_get_verify_result(ssl.inner))
	if res != X509_V_OK {
		return NewOpenSSLError(fmt.Sprintf("libssl: SSL_get_verify_result: %s",
			X509VerifyCertErrorString(res)))
	}
	return nil
}

func X509VerifyCertErrorString(n int64) string {
	return C.GoString(C.go_openssl_X509_verify_cert_error_string(C.long(n)))
}

func SSLGetError(ssl *SSL, ret int) int {
	return int(C.go_openssl_SSL_get_error(ssl.inner, C.int(ret)))
}

func SSLClearError() {
	C.go_openssl_ERR_clear_error()
}

type BIO struct {
	inner C.GO_BIO_PTR
}

func CreateBIO(hostname, port string, family, mode int) (*BIO, int, error) {
	cHost := C.CString(hostname)
	cPort := C.CString(port)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPort))
	bio := C.go_openssl_create_bio(cHost, cPort, C.int(family), C.int(mode), C.int(int(debugLogging)))
	if bio == nil {
		return nil, -1, NewOpenSSLError("libssl: create_bio")
	}
	var sockfd C.int
	if r := C.go_openssl_BIO_ctrl(
		bio,
		C.GO_BIO_C_GET_FD,
		C.long(0),
		unsafe.Pointer(&sockfd)); r == -1 {
		return nil, -1, NewOpenSSLError("libssl: create_bio: BIO not initialized")
	}
	return &BIO{inner: bio}, int(sockfd), nil
}

func SSLConfigureBIO(ssl *SSL, bio *BIO, hostname string) error {
	cHost := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHost))
	if r := C.go_openssl_ssl_configure_bio(ssl.inner, bio.inner, cHost,
		C.int(int(debugLogging))); r != 0 {
		return newSSLError("libssl: ssl_configure_bio", SSLGetError(ssl, int(r)))
	}
	return nil
}

func BIOFree(bio *BIO) error {
	if bio == nil {
		return NewOpenSSLError("libssl: BIO_free_all: BIO is nil")
	}
	C.go_openssl_BIO_free_all(bio.inner)
	return nil
}
