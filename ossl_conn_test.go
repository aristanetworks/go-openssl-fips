package ossl_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
	c := ossl.DefaultConfig()
	c.CaFile = ts.CaFile
	c.CaPath = filepath.Dir(ts.CaFile)
	ctx, err := ossl.NewSSLContext(c)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	d := ossl.DefaultDialer(ctx, c)
	conn, err := d.Dial(context.Background(), net.JoinHostPort(host, port))
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

	if !strings.Contains(response, "HTTP/1.1") {
		t.Errorf("Unexpected response: %s", response)
	}
	fmt.Printf("Response: %s\n", response)
}

func TestSSLConnReadDeadline(t *testing.T) {
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
	c := ossl.DefaultConfig()
	c.ConnTraceEnabled = true
	c.CaFile = ts.CaFile
	c.CaPath = filepath.Dir(ts.CaFile)
	ctx, err := ossl.NewSSLContext(c)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	d := ossl.DefaultDialer(ctx, c)
	conn, err := d.Dial(context.Background(), net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}
	time.Sleep(2 * time.Second)

	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Fatal("Dead should have been reached")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Logf("Deadline reached as expected with err %v", err)
	}
}
