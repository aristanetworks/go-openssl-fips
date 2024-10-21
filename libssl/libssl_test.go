package libssl_test

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/golang-fips/openssl/v2/libssl"
)

// GetVersion returns the OpenSSL version to use for testing.
func GetVersion() string {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	if v != "" {
		switch runtime.GOOS {
		case "linux":
			v = "libssl.so." + v
		case "darwin":
			v = "libssl." + v + ".dylib"
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
		switch runtime.GOOS {
		case "linux":
			v = "libssl.so." + v
		case "darwin":
			v = "libssl." + v + ".dylib"
		}
		if ok, _ := libssl.CheckVersion(v); ok {
			return v
		}
	}
	return "libssl.so"
}

func TestMain(m *testing.M) {
	v := GetVersion()
	fmt.Printf("Using %s\n", v)
	err := libssl.Init(v)
	if err != nil {
		// An error here could mean that this Linux distro does not have a supported OpenSSL version
		// or that there is a bug in the Init code.
		panic(err)
	}
	_ = libssl.SetFIPS(true) // Skip the error as we still want to run the tests on machines without FIPS support.
	fmt.Println("OpenSSL version:", libssl.VersionText())
	fmt.Println("FIPS enabled:", libssl.FIPS())
	status := m.Run()
	for range 5 {
		// Run GC a few times to avoid false positives in leak detection.
		runtime.GC()
		// Sleep a bit to let the finalizers run.
		time.Sleep(10 * time.Millisecond)
	}
	libssl.CheckLeaks()
	os.Exit(status)
}

func TestCheckVersion(t *testing.T) {
	v := GetVersion()
	exists, fips := libssl.CheckVersion(v)
	if !exists {
		t.Fatalf("OpenSSL version %q not found", v)
	}
	if want := libssl.FIPS(); want != fips {
		t.Fatalf("FIPS mismatch: want %v, got %v", want, fips)
	}
}

func TestSSL_connect(t *testing.T) {
	v := GetVersion()
	err := libssl.Init(v)
	if err != nil {
		panic(err)
	}

	method, err := libssl.NewTLSClientMethod()
	if err != nil {
		t.Fatal(err)
	}

	sslCtx, err := libssl.NewSSLCtx(method)
	if err != nil {
		t.Fatal(err)
	}
	defer libssl.SSLCtxFree(sslCtx)

	ssl, err := libssl.NewSSL(sslCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer libssl.SSLFree(ssl)

	// set up TCP connection, similar to default http.Client stack
	conn, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Get file descriptor (this is a duplicate fd)
	file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())

	// Set the fd to this TCP fd
	if err := libssl.SetSSLFd(ssl, fd); err != nil {
		t.Fatal(err)
	}

	// Create TLS connection
	if err := libssl.SSLConnect(ssl); err != nil {
		t.Fatal(err)
	}

	// Send a request over TLS
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err := libssl.SSLWrite(ssl, request); err != nil {
		t.Fatal(err)
	}

	// Receive the response over TLS
	resp, err := libssl.SSLRead(ssl, 1024)
	if err != nil {
		t.Fatal(err)
	}

	// fmt.Println("bytes read", bytesRead)
	fmt.Println(string(resp))
	libssl.CheckLeaks()
}
