package libssl

// #include "golibssl.h"
import "C"
import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

type SslMethod struct {
	inner C.GO_SSL_METHOD_PTR
}

func NewTLSClientMethod() (*SslMethod, error) {
	r := C.go_openssl_TLS_client_method()
	if r == nil {
		return nil, newOpenSSLError("libssl: TLS_client_method")
	}
	return &SslMethod{inner: r}, nil
}

// SslCtx uses a TLS method to configure an SSL connection. It initializes the list of ciphers, the
// session cache setting, the callbacks, the keys and certificates and the options to their default
// values.
//
// SSL_CTX is a "factory" for creating SSL objects. You can create a single SSL_CTX object and
// then create multiple connections (i.e. SSL objects) from it. Note that internally to OpenSSL
// various items that are shared between multiple SSL objects are cached in the SSL_CTX for
// performance reasons. Therefore it is considered best practice to create one SSL_CTX for use by
// multiple SSL objects instead of having one SSL_CTX for each SSL object that you create.
type SslCtx struct {
	inner C.GO_SSL_CTX_PTR
}

func NewSSLCtx(tlsMethod *SslMethod) (*SslCtx, error) {
	r := C.go_openssl_SSL_CTX_new(tlsMethod.inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_CTX_new")
	}
	return &SslCtx{inner: r}, nil
}

func SSLCtxFree(sslCtx *SslCtx) {
	C.go_openssl_SSL_CTX_free(sslCtx.inner)
}

// Ssl holds data for a TLS connection. It inherits the settings of the underlying context ctx:
// connection method, options, verification settings, timeout settings.
type Ssl struct {
	inner C.GO_SSL_PTR
}

func NewSSL(sslCtx *SslCtx) (*Ssl, error) {
	r := C.go_openssl_SSL_new(sslCtx.inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_CTX_new")
	}
	return &Ssl{inner: r}, nil
}

func SSLFree(ssl *Ssl) {
	C.go_openssl_SSL_free(ssl.inner)
}

func SSLClear(ssl *Ssl) {
	C.go_openssl_SSL_clear(ssl.inner)
}

func SetSSLFd(ssl *Ssl, fd int) error {
	r := C.go_openssl_SSL_set_fd(ssl.inner, C.int(fd))
	if r != 1 {
		return newOpenSSLError("libssl: SSL_set_fd")
	}
	return nil
}

func SSLConnect(ssl *Ssl) error {
	r := C.go_openssl_SSL_connect(ssl.inner)
	if r != 1 {
		return newSSLError("libssl: SSL_connect", SSLGetError(ssl, int(r)))
	}
	return nil
}

func SSLConnectWithRetry(ssl *Ssl, timeout time.Duration) error {
	_, _, err := Retry(func() ([]byte, int, error) {
		return nil, 0, SSLConnect(ssl)
	}, timeout)
	if res := SSLGetVerifyResult(ssl); res != X509_V_OK {
		return fmt.Errorf("libssl: SSL_connect: x509: %s", X509VerifyCertErrorString(res))
	}
	return err
}

// SSLShutdown closes an active TLS/SSL connection. It sends the "close notify" shutdown alert to
// the peer.
func SSLShutdown(ssl *Ssl) error {
	r := int(C.go_openssl_SSL_shutdown(ssl.inner))
	switch r {
	case 1:
		return nil
	case 0:
		// Bidirectional shutdown must be performed. SSL_shutdown will need to be called again.
		// TODO: I don't like the idea of doing a recursive call here
		return SSLShutdown(ssl)
	default:
		return newSSLError("libssl: SSL_shutdown", SSLGetError(ssl, r))
	}
}

func SSLShutdownWithRetry(ssl *Ssl, timeout time.Duration) error {
	_, _, err := Retry(func() ([]byte, int, error) {
		return nil, 0, SSLShutdown(ssl)
	}, timeout)
	return err
}

func SSLWriteEx(ssl *Ssl, req []byte) (int, error) {
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		var written C.size_t
		r := C.go_openssl_SSL_write_ex(
			ssl.inner,
			unsafe.Pointer(addr(req)),
			C.size_t(len(req)),
			&written)
		if r != 1 {
			return 0, newSSLError("libssl: SSL_write_ex", SSLGetError(ssl, int(r)))
		}
		return int(written), nil
	}
	// For older versions, use SSL_write
	r := C.go_openssl_SSL_write(ssl.inner, unsafe.Pointer(addr(req)), C.int(len(req)))
	if r <= 0 {
		return 0, newSSLError("libssl: SSL_write", SSLGetError(ssl, int(r)))
	}
	return int(r), nil
}

func SSLWriteExWithRetry(ssl *Ssl, req []byte, timeout time.Duration) (int, error) {
	_, w, err := Retry(func() ([]byte, int, error) {
		w, err := SSLWriteEx(ssl, req)
		return nil, w, err
	}, timeout)
	return w, err
}

func SSLReadEx(ssl *Ssl, size int) ([]byte, int, error) {
	resp := make([]byte, size)
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		var readBytes C.size_t
		r := C.go_openssl_SSL_read_ex(
			ssl.inner,
			unsafe.Pointer(addr(resp)),
			C.size_t(size),
			&readBytes)
		if r != 1 {
			return nil, 0, newSSLError("libssl: SSL_read_ex", SSLGetError(ssl, int(r)))
		}
		return resp[:readBytes], int(readBytes), nil
	}
	// For older versions, use SSL_read
	r := C.go_openssl_SSL_read(
		ssl.inner,
		unsafe.Pointer(addr(resp)),
		C.int(size))
	if r <= 0 {
		return nil, 0, newSSLError("libssl: SSL_read", SSLGetError(ssl, int(r)))
	}
	return resp[:r], int(r), nil
}

func SSLReadExWithRetry(ssl *Ssl, size int, timeout time.Duration) ([]byte, int, error) {
	return Retry(func() ([]byte, int, error) {
		b, n, err := SSLReadEx(ssl, size)
		// if err != nil && SSLGetError(ssl, 0) == SSL_ERROR_ZERO_RETURN {
		// 	return b, n, nil
		// }
		return b, n, err
	}, timeout)
}

func SSLWrite(ssl *Ssl, req []byte) error {
	r := C.go_openssl_SSL_write(ssl.inner, unsafe.Pointer(addr(req)), C.int(len(req)))
	if r <= 0 {
		return newOpenSSLError("libssl: SSL_write")
	}
	return nil
}

func SSLRead(ssl *Ssl, size int) ([]byte, error) {
	resp := make([]byte, size)
	r := C.go_openssl_SSL_read(ssl.inner, unsafe.Pointer(addr(resp)), C.int(size))
	if r <= 0 {
		return nil, newOpenSSLError("libssl: SSL_read")
	}
	return resp[:r], nil
}

func SSLCtxSetMinProtoVersion(ctx *SslCtx, version int) error {
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		r := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_SET_MIN_PROTO_VERSION, C.long(version), nil)
		if r != 1 {
			return newOpenSSLError("libssl: SSL_CTX_set_min_proto_version")
		}
		return nil
	}
	// For older versions, use SSL_CTX_set_options
	return SSLCtxSetOptions(ctx, version)
}

func SSLCtxSetOptions(ctx *SslCtx, version int) error {
	options := C.long(0)
	switch version {
	case C.GO_TLS1_VERSION:
		options = C.GO_SSL_OP_NO_SSLv2 | C.GO_SSL_OP_NO_SSLv3
	case C.GO_TLS1_1_VERSION:
		options = C.GO_SSL_OP_NO_SSLv2 | C.GO_SSL_OP_NO_SSLv3 | C.GO_SSL_OP_NO_TLSv1
	case C.GO_TLS1_2_VERSION:
		options = C.GO_SSL_OP_NO_SSLv2 | C.GO_SSL_OP_NO_SSLv3 | C.GO_SSL_OP_NO_TLSv1 | C.GO_SSL_OP_NO_TLSv1_1
	default:
		return errors.New("libssl: SSL_CTX_set_options: Unsupported TLS version")
	}
	// get options call
	oldMask := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_OPTIONS, C.long(0), nil)
	newMask := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_OPTIONS, options, nil)
	if oldMask == newMask {
		return newOpenSSLError("libssl: SSL_CTX_set_options")
	}
	return nil
}

func SSLSet1Host(ssl *Ssl, hostname string) error {
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		cHostname := C.CString(hostname)
		defer C.free(unsafe.Pointer(cHostname))
		r := C.go_openssl_SSL_set1_host(ssl.inner, cHostname)
		if r != 1 {
			return newOpenSSLError("libssl: SSL_set1_host")
		}
		return nil
	}
	param, err := SSLGet0Param(ssl)
	if err != nil {
		return err
	}
	if err := X509VerifyParamSet1Host(param, hostname); err != nil {
		return err
	}
	return SSLSet1Param(ssl, param)
}

func SSLSet1Param(ssl *Ssl, param *X509VerifyParam) error {
	if ret := C.go_openssl_SSL_set1_param(ssl.inner, param.inner); ret != 1 {
		return newOpenSSLError("libssl: SSL_set1_param")
	}
	return nil
}

func SSLGet0Param(ssl *Ssl) (*X509VerifyParam, error) {
	param := C.go_openssl_SSL_get0_param(ssl.inner)
	if param == nil {
		return nil, newOpenSSLError("libssl: SSL_get0_param")
	}
	return &X509VerifyParam{inner: param}, nil
}

type X509VerifyParam struct {
	inner C.GO_X509_VERIFY_PARAM_PTR
}

func NewX509VerifyParam() *X509VerifyParam {
	param := C.go_openssl_X509_VERIFY_PARAM_new()
	return &X509VerifyParam{inner: param}
}

func X509VerifyParamFree(param *X509VerifyParam) {
	C.go_openssl_X509_VERIFY_PARAM_free(param.inner)
}

// X509VerifyParamSetFlags sets flags on an X509_VERIFY_PARAM structure.
// This function is only available in OpenSSL versions prior to 1.1.0.
func X509VerifyParamSetFlags(param *X509VerifyParam, flags int64) error {
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		return fmt.Errorf("X509_VERIFY_PARAM_set_flags is not available in OpenSSL 1.1.0 and later")
	}
	result := C.go_openssl_X509_VERIFY_PARAM_set_flags(param.inner, C.long(flags))
	if result != 1 {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_set_flags")
	}
	return nil
}

// X509VerifyParamSet1Host sets the expected DNS hostname in the X509_VERIFY_PARAM structure.
// This function is only available in OpenSSL versions prior to 1.1.0.
func X509VerifyParamSet1Host(param *X509VerifyParam, hostname string) error {
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		return fmt.Errorf("X509_VERIFY_PARAM_set1_host is not available in OpenSSL 1.1.0 and later")
	}

	cHostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHostname))

	result := C.go_openssl_X509_VERIFY_PARAM_set1_host(
		param.inner,
		cHostname,
		C.size_t(len(hostname)))
	if result != 1 {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_set1_host")
	}
	return nil
}

// SSLSetHostFlags sets the host flags for certificate verification.
// This function uses X509_VERIFY_PARAM_set_flags for OpenSSL versions prior to 1.1.0,
// and SSL_set1_host for newer versions.
func SSLSetHostFlags(ssl *Ssl, hostname string, flags int64) error {
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		return SSLSet1Host(ssl, hostname)
	}

	// For older versions, we need to get the X509_VERIFY_PARAM, set the flags, and then set the hostname
	ret := C.go_openssl_SSL_get0_param(ssl.inner)
	if ret == nil {
		return newOpenSSLError("libssl: SSL_get0_param")
	}

	param := &X509VerifyParam{inner: ret}
	if err := X509VerifyParamSetFlags(param, flags); err != nil {
		return err
	}

	cHostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHostname))

	if C.go_openssl_X509_VERIFY_PARAM_set1_host(
		param.inner,
		cHostname,
		C.size_t(len(hostname))) != 1 {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_set1_host")
	}

	return nil
}

type SslVerifyCallback struct {
	inner C.GO_SSL_verify_cb_PTR
}

func SSLCtxSetVerify(ctx *SslCtx, mode int, callback SslVerifyCallback) {
	C.go_openssl_SSL_CTX_set_verify(ctx.inner, C.int(mode), callback.inner)
}

func SSLCtxSetDefaultVerifyPaths(ctx *SslCtx) error {
	r := C.go_openssl_SSL_CTX_set_default_verify_paths(ctx.inner)
	if r != 1 {
		return newOpenSSLError("libssl: SSL_CTX_set_default_verify_paths")
	}
	return nil
}

func SSLSetTLSExtHostName(ssl *Ssl, name string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	r := C.go_openssl_SSL_ctrl(
		ssl.inner,
		C.GO_SSL_CTRL_SET_TLSEXT_HOSTNAME,
		C.GO_TLSEXT_NAMETYPE_host_name,
		unsafe.Pointer(cName))
	if r != 1 {
		return newOpenSSLError("libssl: SSL_set_tlsext_host_name")
	}
	return nil
}

func SSLGetVerifyResult(ssl *Ssl) int64 {
	return int64(C.go_openssl_SSL_get_verify_result(ssl.inner))
}

func X509VerifyCertErrorString(n int64) string {
	return C.GoString(C.go_openssl_X509_verify_cert_error_string(C.long(n)))
}

func SSLGetError(ssl *Ssl, ret int) int {
	return int(C.go_openssl_SSL_get_error(ssl.inner, C.int(ret)))
}