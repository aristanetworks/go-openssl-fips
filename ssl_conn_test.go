package client_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	ossl "github.com/golang-fips/openssl/v2"
	"github.com/golang-fips/openssl/v2/internal/testutils"
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
	conn, err := d.DialTLSContext(context.Background(), "tcp", net.JoinHostPort(host, port))
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
