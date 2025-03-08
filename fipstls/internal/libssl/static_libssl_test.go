//go:build static

package libssl_test

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

func TestMain(m *testing.M) {
	_ = libssl.SetFIPS(
		true,
	) // Skip the error as we still want to run the tests on machines without FIPS support.
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

func TestSSL_connect(t *testing.T) {
	defer testutils.LeakCheck(t)

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

	// create blocking bio
	bio, _, err := libssl.CreateBIO("example.com", "443", syscall.AF_INET, 0)
	if err != nil {
		t.Fatal("Failed to create BIO object:", err)
	}
	if err := libssl.SSLConfigureBIO(ssl, bio, "example.com"); err != nil {
		t.Fatal("Failed to configure SSL with BIO object:", err)
	}

	// Create TLS connection
	if err := libssl.SSLConnect(ssl); err != nil {
		t.Fatal(err)
	}

	// Send a request over TLS
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := libssl.SSLWriteEx(ssl, request); err != nil {
		t.Fatal(err)
	}

	// Receive the response over TLS
	resp, _, err := libssl.SSLReadEx(ssl, 1024)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Response was %v bytes.\n", len(resp))
}

func TestBlockingClient(t *testing.T) {
	defer testutils.LeakCheck(t)
	var hostname, port = "example.com", "443"
	// Create an SSL_CTX
	method, err := libssl.NewTLSClientMethod()
	if err != nil {
		t.Fatal("Failed to create TLS client method:", err)
	}

	ctx, err := libssl.NewSSLCtx(method)
	if err != nil {
		t.Fatal("Failed to create TLS client method:", err)
	}
	defer libssl.SSLCtxFree(ctx)

	if err := libssl.SSLCtxConfigure(ctx, &libssl.CtxConfig{
		VerifyMode: libssl.SSL_VERIFY_PEER,
		MinTLS:     libssl.TLS1_2_VERSION,
	}); err != nil {
		t.Fatal("Failed to configure SSLCtx:", err)
	}

	// Create an SSL object
	ssl, err := libssl.NewSSL(ctx)
	if err != nil {
		t.Fatal("Failed to create SSL object:", err)
	}
	defer libssl.SSLFree(ssl)

	// create blocking bio
	bio, _, err := libssl.CreateBIO(hostname, port, syscall.AF_INET, 0)
	if err != nil {
		t.Fatal("Failed to create BIO object:", err)
	}
	if err := libssl.SSLConfigureBIO(ssl, bio, hostname); err != nil {
		t.Fatal("Failed to configure SSL with BIO object:", err)
	}

	// Perform the SSL handshake
	if err := libssl.SSLConnect(ssl); err != nil {
		t.Error("Failed to connect to the server:", err)
		if err := libssl.SSLGetVerifyResult(ssl); err != nil {
			t.Error("Verify error:", err)
		}
		t.Fatal(err)
	}

	// Write an HTTP GET request
	request := fmt.Sprintf("GET / HTTP/1.1\r\nConnection: close\r\nHost: %s\r\n\r\n", hostname)
	if _, err := libssl.SSLWriteEx(ssl, []byte(request)); err != nil {
		t.Fatal("Failed to write HTTP request:", err)
	}

	// Read the response
	var resp []byte
	var n int
	for {
		resp, n, err = libssl.SSLReadEx(ssl, 4096)
		if err != nil {
			if libssl.SSLGetError(ssl, 0) == libssl.SSL_ERROR_ZERO_RETURN {
				break
			}
			t.Error("Failed reading data:", err)
			t.Fatal(err)
		}
		// os.Stdout.Write(resp[:n])
		t.Logf("Response chunk was %v bytes.\n", len(resp[:n]))
	}

	// Shutdown the SSL connection if there is no connection errors, otherwise we need to free
	// connection resources.
	if err := libssl.SSLShutdown(ssl); err != nil {
		t.Error("Error shutting down SSL connection:", err)
		t.Error("Freeing resources explicitly")
		libssl.SSLFree(ssl)
		libssl.SSLCtxFree(ctx)
		t.Fatal(err)
	}
	t.Log("Connection closed successfully")
}
