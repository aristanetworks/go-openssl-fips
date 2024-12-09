package libssl

// #include "golibssl.h"
import "C"
import (
	"fmt"
	"unsafe"
)

type SSLMethod struct {
	inner C.GO_SSL_METHOD_PTR
}

func NewTLSMethod() (*SSLMethod, error) {
	r := C.go_openssl_TLS_method()
	if r == nil {
		return nil, newOpenSSLError("libssl: TLS_method")
	}
	return &SSLMethod{inner: r}, nil
}

func NewTLSClientMethod() (*SSLMethod, error) {
	r := C.go_openssl_TLS_client_method()
	if r == nil {
		return nil, newOpenSSLError("libssl: TLS_client_method")
	}
	return &SSLMethod{inner: r}, nil
}

func NewTLSServerMethod() (*SSLMethod, error) {
	r := C.go_openssl_TLS_server_method()
	if r == nil {
		return nil, newOpenSSLError("libssl: TLS_server_method")
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
		return nil, newOpenSSLError("libssl: SSL_CTX_new: SSL_method is nil")
	}
	r := C.go_openssl_SSL_CTX_new(tlsMethod.inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_CTX_new")
	}
	return &SSLCtx{inner: r}, nil
}

func SSLCtxFree(sslCtx *SSLCtx) error {
	if sslCtx == nil {
		return newOpenSSLError("libssl: SSL_CTX_free: SSL_CTX is nil")
	}
	C.go_openssl_SSL_CTX_free(sslCtx.inner)
	return nil
}

// SSLCtxSetReadAhead
func SSLCtxSetReadAhead(ctx *SSLCtx, yes int) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_read_ahead: SSL_CTX is nil")
	}
	C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_SET_READ_AHEAD, C.long(yes), nil)
	return nil
}

func SSLCtxSetMaxProtoVersion(ctx *SSLCtx, version int64) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_min_proto_version: SSL_CTX is nil")
	}
	if versionAtOrAbove(1, 1, 0) {
		r := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_SET_MAX_PROTO_VERSION, C.long(version), nil)
		if r != 1 {
			return newOpenSSLError("libssl: SSL_CTX_set_min_proto_version")
		}
		return nil
	}
	// For older versions, use SSL_CTX_set_options
	return SSLCtxSetOptions(ctx, version)
}

func SSLCtxSetMinProtoVersion(ctx *SSLCtx, version int64) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_min_proto_version: SSL_CTX is nil")
	}
	if versionAtOrAbove(1, 1, 0) {
		r := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_SET_MIN_PROTO_VERSION, C.long(version), nil)
		if r != 1 {
			return newOpenSSLError("libssl: SSL_CTX_set_min_proto_version")
		}
		return nil
	}
	// For older versions, use SSL_CTX_set_options
	options := int64(0)
	switch version {
	case C.GO_TLS1_VERSION:
		options = C.GO_SSL_OP_NO_SSLv2 | C.GO_SSL_OP_NO_SSLv3
	case C.GO_TLS1_1_VERSION:
		options = C.GO_SSL_OP_NO_SSLv2 | C.GO_SSL_OP_NO_SSLv3 | C.GO_SSL_OP_NO_TLSv1
	case C.GO_TLS1_2_VERSION:
		options = C.GO_SSL_OP_NO_SSLv2 | C.GO_SSL_OP_NO_SSLv3 | C.GO_SSL_OP_NO_TLSv1 | C.GO_SSL_OP_NO_TLSv1_1
	default:
		return fmt.Errorf("libssl: SSL_CTX_set_options: Unsupported TLS version: %v", version)
	}
	return SSLCtxSetOptions(ctx, options)
}

func SSLCtxSetOptions(ctx *SSLCtx, options int64) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_options: SSL_CTX is nil")
	}
	// get options call
	oldMask := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_OPTIONS, C.long(0), nil)
	newMask := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_OPTIONS, C.long(options), nil)
	if oldMask != 0 && oldMask == newMask {
		return newOpenSSLError("libssl: SSL_CTX_set_options")
	}
	return nil
}

func SSLCtxSetMode(ctx *SSLCtx, mode int64) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_mode: SSL_CTX is nil")
	}
	if versionAtOrAbove(1, 1, 0) {
		oldMask := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_MODE, 0, nil)
		newMask := C.go_openssl_SSL_CTX_ctrl(ctx.inner, C.GO_SSL_CTRL_MODE, C.long(mode), nil)
		if oldMask != 0 && oldMask == newMask {
			return newOpenSSLError("libssl: SSL_CTX_set_mode")
		}
	}
	return newOpenSSLError("libssl: SSL_CTX_set_mode not implemented for OpenSSL < 1.1.1")
}

func SSLCtxSetDefaultVerifyPaths(ctx *SSLCtx) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_default_verify_paths: SSL_CTX is nil")
	}
	if r := int(C.go_openssl_SSL_CTX_set_default_verify_paths(ctx.inner)); r != 1 {
		return newOpenSSLError("libssl: SSL_CTX_set_default_verify_paths")
	}
	return nil
}

// SSLCtxLoadVerifyLocations specifies locations for ctx, at which CA certificates for verification
// purposes are located. The certificates available via CAfile and CApath are trusted.
//
// When looking up CA certificates, the OpenSSL library will first search the certificates in
// CAfile, then those in CApath.
func SSLCtxLoadVerifyLocations(ctx *SSLCtx, caFile, caPath string) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_load_verify_locations: SSL_CTX is nil")
	}
	cFile := C.CString(caFile)
	cPath := C.CString(caPath)
	defer C.free(unsafe.Pointer(cFile))
	defer C.free(unsafe.Pointer(cPath))
	if r := int(C.go_openssl_SSL_CTX_load_verify_locations(ctx.inner, cFile, cPath)); r != 1 {
		return newOpenSSLError("libssl: SSL_CTX_load_verify_locations")
	}
	return nil
}

type SSLVerifyCallback struct {
	inner C.GO_SSL_verify_cb_PTR
}

func SSLCtxSetVerify(ctx *SSLCtx, mode int, callback SSLVerifyCallback) error {
	if ctx == nil {
		return newOpenSSLError("libssl: SSL_CTX_set_verify: SSL_CTX is nil")
	}
	C.go_openssl_SSL_CTX_set_verify(ctx.inner, C.int(mode), callback.inner)
	return nil
}

// SSL holds data for a TLS connection. It inherits the settings of the underlying context ctx:
// connection method, options, verification settings, timeout settings.
type SSL struct {
	inner C.GO_SSL_PTR
}

func NewSSL(sslCtx *SSLCtx) (*SSL, error) {
	if sslCtx == nil {
		return nil, newOpenSSLError("libssl: SSL_new: SSL_CTX is nil")
	}
	r := C.go_openssl_SSL_new(sslCtx.inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_new")
	}
	return &SSL{inner: r}, nil
}

func SSLFree(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_clear: SSL is nil")
	}
	C.go_openssl_SSL_free(ssl.inner)
	return nil
}

func SSLClear(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_clear: SSL is nil")
	}
	C.go_openssl_SSL_clear(ssl.inner)
	return nil
}

func SetSSLFd(ssl *SSL, fd int) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_fd: SSL is nil")
	}
	if r := C.go_openssl_SSL_set_fd(ssl.inner, C.int(fd)); r != 1 {
		return newOpenSSLError("libssl: SSL_set_fd")
	}
	return nil
}

func SetSSLReadWriteFd(ssl *SSL, rfd int, wfd int) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_fd: SSL is nil")
	}
	if r := C.go_openssl_SSL_set_rfd(ssl.inner, C.int(rfd)); r != 1 {
		return newOpenSSLError("libssl: SSL_set_rfd")
	}
	if r := C.go_openssl_SSL_set_wfd(ssl.inner, C.int(wfd)); r != 1 {
		return newOpenSSLError("libssl: SSL_set_wfd")
	}
	return nil
}

func SSLConnect(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_connect: SSL is nil")
	}
	if r := C.go_openssl_SSL_connect(ssl.inner); r != 1 {
		return newSSLError("libssl: SSL_connect", SSLGetError(ssl, int(r)))
	}
	return nil
}

func SSLDoHandshake(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_do_handshake: SSL is nil")
	}
	if r := C.go_openssl_SSL_do_handshake(ssl.inner); r != 1 {
		return newSSLError("libssl: SSL_connect", SSLGetError(ssl, int(r)))
	}
	return nil
}

func SSLSetConnectState(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_connect_state: SSL is nil")
	}
	C.go_openssl_SSL_set_connect_state(ssl.inner)
	return nil
}

func SSLSetAcceptState(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_accept_state: SSL is nil")
	}
	C.go_openssl_SSL_set_accept_state(ssl.inner)
	return nil
}

// SSLShutdown closes an active TLS/SSL connection. It sends the "close notify" shutdown alert to
// the peer.
func SSLShutdown(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_shutdown: SSL is nil")
	}
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

// SSLPending
func SSLPending(ssl *SSL) int {
	if ssl != nil {
		return 0
	}
	return int(C.go_openssl_SSL_pending(ssl.inner))
}

// SSLGetShutdown returns the shutdown mode of [SSL].
func SSLGetShutdown(ssl *SSL) int {
	if ssl == nil {
		return C.GO_SSL_RECEIVED_SHUTDOWN
	}
	return int(C.go_openssl_SSL_get_shutdown(ssl.inner))
}

// SSLSetShutdown sets the shutdown state of [SSL] to mode.
func SSLSetShutdown(ssl *SSL, mode int) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_shutdown: SSL is nil")
	}
	C.go_openssl_SSL_set_shutdown(ssl.inner, C.int(mode))
	return nil
}

func SSLWriteEx(ssl *SSL, req []byte) (int, error) {
	if ssl == nil {
		return 0, newOpenSSLError("libssl: SSL_write_ex: SSL is nil")
	}
	cBytes := C.CBytes(req)
	defer C.free(cBytes)
	if versionAtOrAbove(1, 1, 0) {
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
	// For older versions, use SSL_write
	r := C.go_openssl_SSL_write(ssl.inner, cBytes, C.int(len(req)))
	if r <= 0 {
		return 0, newSSLError("libssl: SSL_write", SSLGetError(ssl, int(r)))
	}
	return int(r), nil
}

func SSLReadEx(ssl *SSL, size int64) ([]byte, int, error) {
	if ssl == nil {
		return nil, 0, newOpenSSLError("libssl: SSL_read_ex: SSL is nil")
	}
	cBuf := C.malloc(C.size_t(size))
	defer C.free(cBuf)
	if versionAtOrAbove(1, 1, 0) {
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
	// For older versions, use SSL_read
	r := C.go_openssl_SSL_read(
		ssl.inner,
		cBuf,
		C.int(size))
	if r <= 0 {
		return nil, 0, newSSLError("libssl: SSL_read", SSLGetError(ssl, int(r)))
	}
	return C.GoBytes(cBuf, r), int(r), nil
}

func SSLWrite(ssl *SSL, req []byte) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_write: SSL_CTX is nil")
	}
	cBytes := C.CBytes(req)
	defer C.free(cBytes)
	r := C.go_openssl_SSL_write(ssl.inner, cBytes, C.int(len(req)))
	if r <= 0 {
		return newOpenSSLError("libssl: SSL_write")
	}
	return nil
}

func SSLRead(ssl *SSL, size int64) ([]byte, error) {
	if ssl == nil {
		return nil, newOpenSSLError("libssl: SSL_read: SSL_CTX is nil")
	}
	resp := make([]byte, size)
	r := C.go_openssl_SSL_read(ssl.inner, unsafe.Pointer(addr(resp)), C.int(size))
	if r <= 0 {
		return nil, newOpenSSLError("libssl: SSL_read")
	}
	return resp[:r], nil
}

func SSLSetMode(ssl *SSL, mode int64) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_mode: SSL is nil")
	}
	if versionAtOrAbove(1, 1, 0) {
		oldMask := C.go_openssl_SSL_ctrl(ssl.inner, C.GO_SSL_CTRL_MODE, 0, nil)
		newMask := C.go_openssl_SSL_ctrl(ssl.inner, C.GO_SSL_CTRL_MODE, C.long(mode), nil)
		if oldMask != 0 && oldMask == newMask {
			return newOpenSSLError("libssl: SSL_set_mode")
		}
	}
	return newOpenSSLError("libssl: SSL_set_mode not implemented for OpenSSL < 1.1.1")
}

func SSLSet1Host(ssl *SSL, hostname string) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set1_host: SSL is nil")
	}
	if versionAtOrAbove(1, 1, 0) {
		cHostname := C.CString(hostname)
		defer C.free(unsafe.Pointer(cHostname))
		r := C.go_openssl_SSL_set1_host(ssl.inner, cHostname)
		if r != 1 {
			return newSSLError("libssl: SSL_set1_host", SSLGetError(ssl, int(r)))
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

func SSLSet1Param(ssl *SSL, param *X509VerifyParam) error {
	if ssl == nil {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_free: SSL is nil")
	}
	if param == nil {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_free: X509_VERIFY_PARAM is nil")
	}
	if r := C.go_openssl_SSL_set1_param(ssl.inner, param.inner); r != 1 {
		return newSSLError("libssl: SSL_set1_param", SSLGetError(ssl, int(r)))
	}
	return nil
}

func SSLGet0Param(ssl *SSL) (*X509VerifyParam, error) {
	param := C.go_openssl_SSL_get0_param(ssl.inner)
	if param == nil {
		return nil, newOpenSSLError("libssl: SSL_get0_param: X509_VERIFY_PARAM is nil")
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

func X509VerifyParamFree(param *X509VerifyParam) error {
	if param == nil {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_free: X509_VERIFY_PARAM is nil")
	}
	C.go_openssl_X509_VERIFY_PARAM_free(param.inner)
	return nil
}

// X509VerifyParamSetFlags sets flags on an X509_VERIFY_PARAM structure.
// This function is only available in OpenSSL versions prior to 1.1.0.
func X509VerifyParamSetFlags(param *X509VerifyParam, flags int64) error {
	if param == nil {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_set_flags: X509_VERIFY_PARAM is nil")
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
	if param == nil {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_set1_host: X509_VERIFY_PARAM is nil")
	}
	if versionAtOrAbove(1, 1, 0) {
		return fmt.Errorf("libssl: X509_VERIFY_PARAM_set1_host is not available in OpenSSL 1.1.0 and later")
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
func SSLSetHostFlags(ssl *SSL, hostname string, flags int64) error {
	if ssl == nil {
		return newOpenSSLError("libssl: X509_VERIFY_PARAM_set1_host: SSL is nil")
	}
	if vMajor == 3 || vMajor >= 1 && vMinor >= 1 {
		return SSLSet1Host(ssl, hostname)
	}

	// For older versions, we need to get the X509_VERIFY_PARAM, set the flags, and then set the hostname
	param, err := SSLGet0Param(ssl)
	if err != nil {
		return err
	}

	if err := X509VerifyParamSetFlags(param, flags); err != nil {
		return err
	}

	cHostname := C.CString(hostname)
	defer C.free(unsafe.Pointer(cHostname))

	if r := C.go_openssl_X509_VERIFY_PARAM_set1_host(
		param.inner,
		cHostname,
		C.size_t(len(hostname))); r != 1 {
		return newSSLError("libssl: X509_VERIFY_PARAM_set1_host", SSLGetError(ssl, int(r)))
	}

	return nil
}

func SSLSetTLSExtHostName(ssl *SSL, name string) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_tlsext_hostname: SSL is nil")
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	if r := C.go_openssl_SSL_ctrl(
		ssl.inner,
		C.GO_SSL_CTRL_SET_TLSEXT_HOSTNAME,
		C.GO_TLSEXT_NAMETYPE_host_name,
		unsafe.Pointer(cName)); r != 1 {
		return newSSLError("libssl: SSL_set_tlsext_host_name", SSLGetError(ssl, int(r)))
	}
	return nil
}

func SSLGetVerifyResult(ssl *SSL) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_get_verify_result: SSL is nil")
	}
	res := int64(C.go_openssl_SSL_get_verify_result(ssl.inner))
	if res != X509_V_OK {
		return newOpenSSLError(fmt.Sprintf("libssl: SSL_get_verify_result: %s",
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

type SSLSession struct {
	inner C.GO_SSL_SESSION_PTR
}

func SSLGetSession(ssl *SSL) (*SSLSession, error) {
	if ssl == nil {
		return nil, newOpenSSLError("libssl: SSL_get1_session: SSL is nil")
	}
	r := C.go_openssl_SSL_get1_session(ssl.inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_get1_session")
	}
	return &SSLSession{inner: r}, nil
}

func SSLSetSession(ssl *SSL, session *SSLSession) error {
	if ssl == nil {
		return newOpenSSLError("libssl: SSL_set_session: SSL is nil")
	}
	if session == nil {
		return newOpenSSLError("libssl: SSL_set_session: SSL_session is nil")
	}
	r := int(C.go_openssl_SSL_set_session(ssl.inner, session.inner))
	if r == 0 {
		return newOpenSSLError("libssl: SSL_set_session")
	}
	return nil
}

func SSLSessionFree(session *SSLSession) error {
	if session == nil {
		return newOpenSSLError("libssl: SSL_SESSION_free: SSL_session is nil")
	}
	C.go_openssl_SSL_SESSION_free(session.inner)
	return nil
}

func SSLDialHost(ssl *SSL, hostname, port string, family, mode int) error {
	if ssl == nil {
		return newOpenSSLError("libssl: dial_host: SSL is nil")
	}
	if !versionAtOrAbove(1, 1, 0) {
		return newOpenSSLError("libssl: dial_host: not implemented for OpenSSL < 1.1.1")
	}
	cHost := C.CString(hostname)
	cPort := C.CString(port)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPort))
	if r := C.go_openssl_dial_host(
		ssl.inner,
		cHost,
		cPort,
		C.int(family),
		C.int(mode)); r != 0 {
		return newSSLError("libssl: dial_host", SSLGetError(ssl, int(r)))
	}
	return nil
}

func SSLGetFd(ssl *SSL) (int, error) {
	if ssl == nil {
		return 0, newOpenSSLError("libssl: SSL_get_fd: SSL is nil")
	}
	r := C.go_openssl_SSL_get_fd(ssl.inner)
	if r == -1 {
		return int(r), newSSLError("libssl: SSL_get_fd", SSLGetError(ssl, int(r)))
	}
	return int(r), nil
}
