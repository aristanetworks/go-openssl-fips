package client_test

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-fips/openssl/v2/client"
	"github.com/golang-fips/openssl/v2/client/conn"
	"github.com/golang-fips/openssl/v2/client/internal/testutils"
)

var (
	caFile = "./internal/testutils/certs/cert.pem"
	caPath = "./internal/testutils/certs"
)

func TestSSLClientGet(t *testing.T) {
	ts := testutils.NewServer(t)
	defer ts.Close()

	sslClient, err := client.NewSSLClient("", 10 * time.Second, &conn.Config{CaFile: caFile, CaPath: caPath})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{"Get", "/get", http.StatusOK},
		{"Not Found", "/status/404", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sslClient.Get(ts.URL + tt.path)
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
	ts := testutils.NewServer(t)
	defer ts.Close()

	sslClient, err := client.NewSSLClient("", 10 * time.Second, &conn.Config{CaFile: caFile, CaPath: caPath})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Post", func(t *testing.T) {
		jsonData, _ := json.Marshal([]byte(`{ "test": "key"}`))
		resp, err := sslClient.Post(ts.URL+"/post", "application/json",
			strings.NewReader(string(jsonData)))
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		// Read the response body
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		// Compare JSON (ignoring order)
		var expected, actual interface{}
		err = json.Unmarshal([]byte(jsonData), &expected)
		if err != nil {
			t.Fatal(err)
		}
		err = json.Unmarshal(respBody, &actual)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected JSON:\n%s\nBut got:\n%s", jsonData, string(respBody))
		}
	})
}

// TODO: benchmark against default http.Client