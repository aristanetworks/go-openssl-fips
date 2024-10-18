package client_test

import (
	"bufio"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-fips/openssl/v2/client"
)

func TestSSLConn(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	// Add a test item
	ts.store.SetItem(Item{ID: "1", Name: "Test Item"})

	host, _ := url.Parse(ts.server.URL)
	conn, err := client.NewSSLConn(host, 10)
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	request := fmt.Sprintf("GET /items/1 HTTP/1.1\r\nHost: %s\r\n\r\n", host.Hostname())
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
