package libssl

// #include "golibssl.h"
import "C"
import (
	"os"
	"runtime"
	"unsafe"
)

// getVersion returns the OpenSSL version to use for testing.
func getVersion() string {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	if v != "" {
		if runtime.GOOS == "linux" {
			return "libssl.so." + v
		}
		return v
	}
	// Try to find a supported version of OpenSSL on the system.
	// This is useful for local testing, where the user may not
	// have GO_OPENSSL_VERSION_OVERRIDE set.
	versions := []string{"3", "1.1.1", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}
	if runtime.GOOS == "windows" {
		if runtime.GOARCH == "amd64" {
			versions = []string{"libssl-3-x64", "libssl-3", "libssl-1_1-x64", "libssl-1_1", "libeay64", "libeay32"}
		} else {
			versions = []string{"libssl-3", "libssl-1_1", "libeay32"}
		}
	}
	for _, v = range versions {
		if runtime.GOOS == "windows" {
			v += ".dll"
		} else if runtime.GOOS == "darwin" {
			v = "libssl." + v + ".dylib"
		} else {
			v = "libssl.so." + v
		}
		if ok, _ := CheckVersion(v); ok {
			return v
		}
	}
	return "libssl.so"
}

var Version string

func init() {
	Version = getVersion()
}

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

// SslCtx uses a TLS method to establish an SSL connection. It initializes the list of ciphers, the
// session cache setting, the callbacks, the keys and certificates and the options to their default
// values.
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
