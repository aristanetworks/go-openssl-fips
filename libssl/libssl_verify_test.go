package libssl_test

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/golang-fips/openssl/v2/libssl"
)

func init() {
	err := libssl.Init(libssl.Version)
	if err != nil {
		panic(err)
	}
}

func TestBlockingClient(t *testing.T) {
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

	// Configure the client to abort the handshake if certificate verification fails
	libssl.SSLCtxSetVerify(ctx, libssl.SSL_VERIFY_PEER, libssl.SslVerifyCallback{})

	// Use the default trusted certificate store
	if err := libssl.SSLCtxSetDefaultVerifyPaths(ctx); err != nil {
		t.Fatal("Failed to set the default trusted certificate store:", err)
	}

	// Set minimum TLS version to TLSv1.2
	if err := libssl.SSLCtxSetMinProtoVersion(ctx, libssl.TLS1_2_VERSION); err != nil {
		t.Fatal("Failed to set the minimum TLS protocol version:", err)
	}

	// Create an SSL object
	ssl, err := libssl.NewSSL(ctx)
	if err != nil {
		t.Fatal("Failed to create SSL object:", err)
	}
	defer libssl.SSLFree(ssl)

	// Create the underlying transport socket using net.Dial
	network := "tcp4"
	conn, err := net.Dial(network, net.JoinHostPort(hostname, port))
	if err != nil {
		t.Fatal("Failed to create socket connection:", err)
	}
	defer conn.Close()

    file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())

	// Associate the socket with the SSL object
	if err := libssl.SetSSLFd(ssl, fd); err != nil {
		t.Fatal("Failed to set SSL file descriptor:", err)
	}

	// Set the SNI hostname
	if err := libssl.SSLSetTLSExtHostName(ssl, hostname); err != nil {
		t.Fatal("Failed to set the SNI hostname:", err)
	}

	// Set the hostname for certificate verification
	if err := libssl.SSLSet1Host(ssl, hostname); err != nil {
		t.Fatal("Failed to set the certificate verification hostname:",  err)
	}

	// Perform the SSL handshake
	if err := libssl.SSLConnect(ssl); err != nil {
		fmt.Println("Failed to connect to the server:", err)
		if res := libssl.SSLGetVerifyResult(ssl); res != libssl.X509_V_OK {
			fmt.Println("Verify error:", libssl.X509VerifyCertErrorString(res))
		}
		t.Fatal(err)
	}

	// Write an HTTP GET request
	request := fmt.Sprintf("GET / HTTP/1.1\r\nConnection: close\r\nHost: %s\r\n\r\n", hostname)
	if _, err := libssl.SSLWriteEx(ssl, []byte(request)); err != nil {
		t.Fatal("Failed to write HTTP request:", err)
	}

	// Read the response
	for {
		resp, n, err := libssl.SSLReadEx(ssl, 4096)
		if err != nil {
			if libssl.SSLGetError(ssl, 0) == libssl.SSL_ERROR_ZERO_RETURN {
				break
			}
			fmt.Println("Failed reading data:", err)
			t.Fatal(err)
		}
		os.Stdout.Write(resp[:n])
	}

	// Shutdown the SSL connection if there is no connection errors, otherwise we need to free
	// connection resources.
	if err := libssl.SSLShutdown(ssl); err != nil {
		fmt.Println("Error shutting down SSL connection:", err)
		fmt.Println("Freeing resources explicitly")
		libssl.SSLFree(ssl)
		libssl.SSLCtxFree(ctx)
		t.Fatal(err)
	}
	fmt.Println("\nConnection closed successfully")
}

func TestNonBlockingClient(t *testing.T) {
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

	// Configure the client to abort the handshake if certificate verification fails
	libssl.SSLCtxSetVerify(ctx, libssl.SSL_VERIFY_PEER, libssl.SslVerifyCallback{})

	// Use the default trusted certificate store
	if err := libssl.SSLCtxSetDefaultVerifyPaths(ctx); err != nil {
		t.Fatal("Failed to set the default trusted certificate store:", err)
	}

	// Set minimum TLS version to TLSv1.2
	if err := libssl.SSLCtxSetMinProtoVersion(ctx, libssl.TLS1_2_VERSION); err != nil {
		t.Fatal("Failed to set the minimum TLS protocol version:", err)
	}

	// Create an SSL object
	ssl, err := libssl.NewSSL(ctx)
	if err != nil {
		t.Fatal("Failed to create SSL object:", err)
	}
	defer libssl.SSLFree(ssl)

	// Create the underlying transport socket using net.Dial
	network := "tcp4"
	conn, err := net.Dial(network, net.JoinHostPort(hostname, port))
	if err != nil {
		t.Fatal("Failed to create socket connection:", err)
	}
	timeout:=30 * time.Second
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal("Failed to set deadline on tcp connection:", err)
	}
	defer conn.Close()

    file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())

	// Associate the socket with the SSL object
	if err := libssl.SetSSLFd(ssl, fd); err != nil {
		t.Fatal("Failed to set SSL file descriptor:", err)
	}

	// Set the SNI hostname
	if err := libssl.SSLSetTLSExtHostName(ssl, hostname); err != nil {
		t.Fatal("Failed to set the SNI hostname:", err)
	}

	// Set the hostname for certificate verification
	if err := libssl.SSLSet1Host(ssl, hostname); err != nil {
		t.Fatal("Failed to set the certificate verification hostname:",  err)
	}

	// Perform the SSL handshake
	if err := libssl.SSLConnectWithRetry(ssl, timeout); err != nil {
		t.Fatal(err)
	}

	// Write an HTTP GET request
	request := fmt.Sprintf("GET / HTTP/1.1\r\nConnection: close\r\nHost: %s\r\n\r\n", hostname)
	if _, err := libssl.SSLWriteExWithRetry(ssl, []byte(request), timeout); err != nil {
		t.Fatal("Failed to write HTTP request:", err)
	}

	// Read the response
	for {
		resp, n, err := libssl.SSLReadExWithRetry(ssl, 4096, timeout)
		if err != nil {
			if libssl.SSLGetError(ssl, 0) == libssl.SSL_ERROR_ZERO_RETURN {
				break
			}
			fmt.Println("Failed reading data:", err)
			t.Fatal(err)
		}
		os.Stdout.Write(resp[:n])
	}

	// Shutdown the SSL connection if there no connection errors.
	if err := libssl.SSLShutdownWithRetry(ssl, timeout); err != nil {
		fmt.Println("Error shutting down SSL connection:", err)
		libssl.SSLFree(ssl)
		libssl.SSLCtxFree(ctx)
		t.Fatal(err)
	}
	fmt.Println("\nConnection closed successfully")
}