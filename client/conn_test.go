package client_test

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/golang-fips/openssl/v2/client"
)

// TODO: should test against a local go https server
func TestSSLConn(t *testing.T) {
	conn, err := client.NewSSLConn("httpbin.org", 10)
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	request := "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
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
