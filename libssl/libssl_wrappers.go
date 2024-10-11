package libssl

// #include "golibssl.h"
import "C"
import "unsafe"

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
		return newOpenSSLError("libssl: SSL_connect")
	}
	return nil
}

func SSLWrite(ssl *Ssl, req []byte) error {
	r := C.go_openssl_SSL_write(ssl.inner, unsafe.Pointer(addr(req)), C.int(len(req)))
	if r <= 0 {
		return newOpenSSLError("libssl: SSL_write")
	}
	return nil
}

func SSLRead(ssl *Ssl, size int) ([]byte, error) {
	resp := make([]byte, 1024)
	r := C.go_openssl_SSL_read(ssl.inner, unsafe.Pointer(addr(resp)), C.int(size))
	if r <= 0 {
		return nil, newOpenSSLError("libssl: SSL_read")
	}
	return resp, nil
}
