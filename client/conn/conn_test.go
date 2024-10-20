package conn_test

import (
	"bufio"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-fips/openssl/v2/client/conn"
	"github.com/golang-fips/openssl/v2/client/internal/testutils"
	"github.com/golang-fips/openssl/v2/libssl"
)

func init() {
    libssl.Init(libssl.Version)
}

func TestSSLConn(t *testing.T) {
	ts := testutils.NewServer(t)
	defer ts.Close()

	// Add a test item
	host, _ := url.Parse(ts.URL)
	conn, err := conn.NewSSLConn(host, 10)
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host.Hostname())
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
