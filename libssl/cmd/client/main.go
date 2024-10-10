package main

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/golang-fips/openssl/v2/libssl"
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
		if ok, _ := libssl.CheckVersion(v); ok {
			return v
		}
	}
	return "libssl.so"
}

func main() {
	v := getVersion()
	err := libssl.Init(v)
	if err != nil {
		panic(err)
	}

	method, err := libssl.DefaultTLSClientMethod()
	if err != nil {
		panic(err)
	}

	sslCtx, err := libssl.NewSSLCtx(method)
	if err != nil {
		panic(err)
	}

	ssl, err := libssl.NewSSL(sslCtx)
	if err != nil {
		panic(err)
	}

	// set up TCP connection, similar to default http.Client stack
	conn, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Get file descriptor (this is a duplicate fd)
	file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())

	// Set the fd to this TCP fd
	if err := libssl.SetSSLFd(ssl, fd); err != nil {
		panic(err)
	}

	// Create TLS connection
	if err := libssl.SSLConnect(ssl); err != nil {
		panic(err)
	}

	// Send a request over TLS
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err := libssl.SSLWrite(ssl, request); err != nil {
		panic(err)
	}

	// Receive the response over TLS
	resp, err := libssl.SSLRead(ssl, 1024)
	if err != nil {
		panic(err)
	}

	// fmt.Println("bytes read", bytesRead)
	fmt.Println(string(resp))
}
