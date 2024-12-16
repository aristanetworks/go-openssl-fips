package ossl_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"reflect"
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

// TestSSLClientGet
func TestSSLClientGet(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)
	ts := testutils.NewTestServer(t)
	defer ts.Close()

	client := ossl.NewTLSClient(ossl.WithCaFile(ts.CaFile))

	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			t.Logf("[Client] Started handshake: url=%s", ts.URL)
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			t.Logf("[Client] Completed handshake: url=%s state=%+v err=%v", ts.URL, connState, err)
		},
		GetConn: func(hostPort string) {
			t.Logf("[Client] Getting connection to: %s", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.Logf("[Client] Got connection: reused=%v idle=%v idleTime=%v",
				info.Reused, info.WasIdle, info.IdleTime)
		},
		PutIdleConn: func(err error) {
			t.Logf("[Client] Putting idle connection back: err=%v", err)
		},
		ConnectDone: func(network, addr string, err error) {
			t.Logf("[Client] Connect done: network=%s addr=%s err=%v", network, addr, err)
		},
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
			req, err := http.NewRequestWithContext(
				httptrace.WithClientTrace(context.Background(), trace),
				"GET",
				ts.URL+tt.path,
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")

			resp, err := client.Do(req)
			t.Logf("Received response: %+v", resp)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Failed to read body: %v", err)
				return
			}
			t.Logf("Response body: %s", body)
		})
	}
}

// TestSSLClientPost
func TestSSLClientPost(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)
	ts := testutils.NewTestServer(t)
	defer ts.Close()

	client := ossl.NewTLSClient(ossl.WithCaFile(ts.CaFile))

	jsonData, _ := json.Marshal([]byte(`
	{ "test": "key",
	  "test1": "key1",
	  "test2": "key2",
	  "test3": "key3",
	  "test4": "key4",
	  "test5": "key5"
	}`))
	t.Run("Post", func(t *testing.T) {
		resp, err := client.Post(ts.URL+"/post", "application/json",
			strings.NewReader(string(jsonData)))
		t.Logf("Received response:\n%+v", resp)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

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

func TestSSLClientPostTrace(t *testing.T) {
	ts := testutils.NewTestServer(t)
	defer ts.Close()

	client := ossl.NewTLSClient(ossl.WithCaFile(ts.CaFile), ossl.WithTimeout(10*time.Second))

	jsonData, _ := json.Marshal([]byte(`
	{ "test": "key",
	  "test1": "key1",
	  "test2": "key2",
	  "test3": "key3",
	  "test4": "key4",
	  "test5": "key5"
	}`))
	req, _ := http.NewRequest("POST", ts.URL+"/post", strings.NewReader(string(jsonData)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			t.Logf("[Client] Started handshake: url=%s", ts.URL)
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			t.Logf("[Client] Completed handshake: url=%s state=%+v err=%v", ts.URL, connState, err)
		},
		ConnectStart: func(network, addr string) {
			t.Logf("[Client] Started connection to address: %s:%s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			t.Logf("[Client] Completed connection to address: %s:%s\n", network, addr)
			t.Logf("[Client] Completed connection to address with error: %+v\n", err)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			t.Logf("[Client] Got Conn: %+v\n", connInfo)
		},
		PutIdleConn: func(err error) {
			t.Logf("[Client] Putting idle connection back: err=%v", err)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Transport.RoundTrip(req)
	t.Logf("Received response:\n%+v", resp)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRoundTripSSL(t *testing.T) {
	t.Skip("local testing only")
	defer testutils.LeakCheckLSAN(t)
	client := ossl.NewTLSClient(ossl.WithTimeout(10 * time.Second))

	// Add HTTP trace for debugging
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			t.Logf("[Client] Started handshake: url=%s", "https://httpbingo.org")
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			t.Logf("[Client] Completed handshake: url=%s state=%+v err=%v", "https://httpbingo.org", connState, err)
		},
		ConnectStart: func(network, addr string) {
			t.Logf("[Client] Started connection to address: %s:%s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			t.Logf("[Client] Completed connection to address: %s:%s\n", network, addr)
			t.Logf("[Client] Completed connection to address with error: %+v\n", err)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			t.Logf("[Client] Got Conn: %+v\n", connInfo)
		},
	}

	tests := []struct {
		method string
		url    string
		body   string
	}{
		{"GET", "https://httpbingo.org/get", ""},
		{"POST", "https://httpbingo.org/post", `{"key":"value"}`},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.url), func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				httptrace.WithClientTrace(context.Background(), trace),
				tc.method,
				tc.url,
				bytes.NewReader([]byte(tc.body)),
			)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			t.Logf("Received response: %v", resp.Status)
		})
	}
}
