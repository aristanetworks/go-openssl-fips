package client_test

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/golang-fips/openssl/v2/client"
)

// TODO: should test against a local go https server
func TestSSLClientGet(t *testing.T) {
	client, err := client.NewSSLClient(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		url            string
		expectedStatus int
	}{
		{"Example.com", "https://example.com", 200},
		{"Httpbin GET", "https://httpbin.org/get", 200},
		{"Httpbin 404", "https://httpbin.org/status/404", 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(tt.url)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			_, err = io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
		})
	}
}

func TestSSLClientPost(t *testing.T) {
	client, err := client.NewSSLClient(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Httpbin POST", func(t *testing.T) {
		resp, err := client.Post("https://httpbin.org/post", "application/json",
			strings.NewReader(""))
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
		if resp.Header.Get("content-type") != "application/json" {
			t.Errorf("Content type not found in response")
		}
	})
}
