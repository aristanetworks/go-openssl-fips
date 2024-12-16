package ossl_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aristanetworks/go-openssl-fips/ossl"
	"github.com/aristanetworks/go-openssl-fips/ossl/internal/testutils"
)

func init() {
	if err := ossl.Init(""); err != nil {
		panic(err)
	}
}

func TestSSLConn(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)
	ts := testutils.NewTestServer(t)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	d := ossl.NewDialer(ossl.NewDefaultTLSContext(
		ossl.WithCaFile(ts.CaFile),
		ossl.WithConnTrace(),
	))
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(string(response), "HTTP/1.1") {
		t.Errorf("Unexpected response: %s", response)
	}
	fmt.Printf("Response: %s\n", string(response))
}

func TestSSLConnReadDeadline(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)
	ts := testutils.NewTestServer(t)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	d := ossl.NewDialer(ossl.NewDefaultTLSContext(
		ossl.WithCaFile(ts.CaFile),
		ossl.WithConnTrace(),
	))
	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}
	time.Sleep(3 * time.Second)

	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Fatal("Deadline should have been reached")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Logf("Deadline reached as expected with err %v", err)
	} else {
		t.Fatalf("Error is not deadline error: %v", err)
	}
}
