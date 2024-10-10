package libssl

// #include "golibssl.h"
import "C"
import "unsafe"

type SSL_METHOD struct {
	Inner C.GO_SSL_METHOD_PTR
}

func DefaultTLSClientMethod() (*SSL_METHOD, error) {
	r := C.go_openssl_TLS_client_method()
	if r == nil {
		return nil, newOpenSSLError("libssl: TLS_client_method")
	}
	return &SSL_METHOD{Inner: r}, nil
}

type SSL_CTX struct {
	Inner C.GO_SSL_CTX_PTR
}

func NewSSLCtx(tlsMethod *SSL_METHOD) (*SSL_CTX, error) {
	r := C.go_openssl_SSL_CTX_new(tlsMethod.Inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_CTX_new")
	}
	return &SSL_CTX{Inner: r}, nil
}

type SSL struct {
	Inner C.GO_SSL_PTR
}

func NewSSL(sslCtx *SSL_CTX) (*SSL, error) {
	r := C.go_openssl_SSL_new(sslCtx.Inner)
	if r == nil {
		return nil, newOpenSSLError("libssl: SSL_CTX_new")
	}
	return &SSL{Inner: r}, nil
}

func SetSSLFd(ssl *SSL, fd int) error {
	r := C.go_openssl_SSL_set_fd(ssl.Inner, C.int(fd))
	if r != 1 {
		return newOpenSSLError("libssl: SSL_set_fd")
	}
	return nil
}

func SSLConnect(ssl *SSL) error {
	r := C.go_openssl_SSL_connect(ssl.Inner)
	if r != 1 {
		return newOpenSSLError("libssl: SSL_connect")
	}
	return nil
}

func SSLWrite(ssl *SSL, req []byte) error {
	r := C.go_openssl_SSL_write(ssl.Inner, unsafe.Pointer(&*addr(req)), C.int(len(req)))
	if r <= 0 {
		return newOpenSSLError("libssl: SSL_write")
	}
	return nil
}

func SSLRead(ssl *SSL, size int) ([]byte, error) {
	resp := make([]byte, 1024)
	r := C.go_openssl_SSL_read(ssl.Inner, unsafe.Pointer(&*addr(resp)), C.int(size))
	if r <= 0 {
		return nil, newOpenSSLError("libssl: SSL_read")
	}
	return resp, nil
}
