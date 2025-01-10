package fipstls_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

func getClientOpts() []fipstls.DialOption {
	o := []fipstls.DialOption{}
	if *enableClientTrace {
		o = append(o, fipstls.WithConnTracingEnabled())
	}
	return o
}

// TestSSLClientGet
func TestSSLClientGet(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	ts := testutils.NewServer(t, *enableServerTrace)
	defer ts.Close()

	client, err := fipstls.NewClient(fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
		getClientOpts()...)
	if err != nil {
		t.Fatal(err)
	}

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
	initTest(t)
	defer testutils.LeakCheck(t)
	ts := testutils.NewServer(t, *enableServerTrace)
	defer ts.Close()

	client, err := fipstls.NewClient(fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
		getClientOpts()...)
	if err != nil {
		t.Fatal(err)
	}

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
	initTest(t)
	ts := testutils.NewServer(t, *enableServerTrace)
	defer ts.Close()

	client, err := fipstls.NewClient(fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
		getClientOpts()...)
	if err != nil {
		t.Fatal(err)
	}

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
	initTest(t)
	defer testutils.LeakCheck(t)
	client, err := fipstls.NewClient(fipstls.NewCtx(), getClientOpts()...)
	if err != nil {
		t.Fatal(err)
	}

	// Add HTTP trace for debugging
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			t.Logf("[Client] Started handshake: url=%s", "https://httpbingo.org")
		},
		TLSHandshakeDone: func(connState tls.ConnectionState, err error) {
			t.Logf("[Client] Completed handshake: url=%s state=%+v err=%v", "https://httpbingo.org",
				connState, err)
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

type Response struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// Progress tracks streaming progress
type Progress struct {
	MessagesRead int64
	TotalBytes   int64
	BytesRead    int64
	BytesPerSec  float64
	LastUpdate   time.Time
}

func TestStreamJSON(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	client, err := fipstls.NewClient(fipstls.NewCtx(), getClientOpts()...)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		n             int
		expectSuccess bool
	}{
		{"Stream 5 messages", 5, true},
		{"Stream 10 messages", 10, true},
		{"Stream 50 messages", 50, true},
		{"Stream 100 messages", 100, true},
	}

	// Create a mutex to protect access to t
	var logMu sync.Mutex

	// Safe logging helper
	safeLog := func(format string, args ...interface{}) {
		logMu.Lock()
		t.Logf(format, args...)
		logMu.Unlock()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("https://httpbingo.org/stream/%d", tt.n)
			progCh := make(chan Progress, 1)
			respCh := make(chan Response, tt.n)
			errCh := make(chan error, 1)

			go func() {
				if err := streamWithProgress(t, client, url, progCh, respCh); err != nil {
					errCh <- err
					close(respCh)
					return
				}
				close(respCh)
				close(errCh)
			}()

			go func() {
				for prog := range progCh {
					safeLog("Progress: Messages=%d, Bytes=%d, Speed=%.2f KB/s",
						prog.MessagesRead,
						prog.BytesRead,
						prog.BytesPerSec/1024)
				}
			}()

			var resp []Response
			for r := range respCh {
				safeLog("Received message: %+v", r)
				resp = append(resp, r)
			}

			if err := <-errCh; err != nil {
				if tt.expectSuccess {
					t.Errorf("Expected success but got error: %v", err)
				}
				return
			}

			// Verify number of messages
			if len(resp) != tt.n {
				t.Errorf("Expected %d messages, got %d", tt.n, len(resp))
			}

			// Verify message IDs are sequential
			for i, msg := range resp {
				if msg.ID != i {
					t.Errorf("Message ID mismatch: expected %d, got %d", i, msg.ID)
				}
			}
		})
	}
}

func streamWithProgress(t *testing.T, client *http.Client, url string, progCh chan<- Progress,
	respCh chan<- Response) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	var bytesRead int64
	var read int64
	startTime := time.Now()
	lastUpdate := startTime

	for {
		var response Response
		err := decoder.Decode(&response)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		read++
		bytesRead = decoder.InputOffset()
		respCh <- response

		now := time.Now()
		duration := now.Sub(lastUpdate)
		if duration >= 100*time.Millisecond {
			progress := Progress{
				MessagesRead: read,
				TotalBytes:   resp.ContentLength,
				BytesRead:    bytesRead,
				BytesPerSec:  float64(bytesRead) / time.Since(startTime).Seconds(),
				LastUpdate:   now,
			}
			progCh <- progress
			lastUpdate = now
		}
	}

	progress := Progress{
		MessagesRead: read,
		TotalBytes:   resp.ContentLength,
		BytesRead:    bytesRead,
		BytesPerSec:  float64(bytesRead) / time.Since(startTime).Seconds(),
		LastUpdate:   time.Now(),
	}
	progCh <- progress
	close(progCh)

	return nil
}

const URL = "https://httpbingo.org/"

var (
	postUrl, _ = url.JoinPath(URL, "post")
	getUrl, _  = url.JoinPath(URL, "get")
)

func BenchmarkClientSSL(b *testing.B) {
	initTest(nil)
	defer testutils.LeakCheck(b)
	osslClient, _ := fipstls.NewClient(fipstls.NewCtx(), getClientOpts()...)

	b.ResetTimer()

	b.Run("Custom OSSL Client GET", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequest("GET", getUrl, nil)
			resp, err := osslClient.Transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var body map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&body)
			if err != nil {
				b.Fatalf("Invalid JSON response: %v", err)
			}
		}
	})

	b.Run("Custom OSSL Client POST", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			payload := []byte(`{"key": "value"}`)
			req, _ := http.NewRequest("POST", postUrl, bytes.NewBuffer(payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := osslClient.Transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()
		}
	})

	b.Run("Custom OSSL Client MIXED", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if rand.Intn(2) == 0 {
				req, _ := http.NewRequest("GET", getUrl, nil)
				resp, err := osslClient.Transport.RoundTrip(req)
				if err != nil {
					b.Fatalf("GET request failed: %v", err)
				}
				defer resp.Body.Close()

				var body map[string]interface{}
				err = json.NewDecoder(resp.Body).Decode(&body)
				if err != nil {
					b.Fatalf("Invalid JSON response: %v", err)
				}
			} else {
				payload := []byte(`{"key": "value"}`)
				req, _ := http.NewRequest("POST", postUrl, bytes.NewBuffer(payload))
				req.Header.Set("Content-Type", "application/json")
				resp, err := osslClient.Transport.RoundTrip(req)
				if err != nil {
					b.Fatalf("POST request failed: %v", err)
				}
				defer resp.Body.Close()
			}
		}
	})
}

func BenchmarkClientCachedSSL(b *testing.B) {
	initTest(nil)
	defer testutils.LeakCheck(b)
	ctx, err := fipstls.NewUnsafeCtx()
	if err != nil {
		b.Fatal(err)
	}
	osslClient, err := fipstls.NewClient(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer ctx.Close()
	b.ResetTimer()

	b.Run("Custom OSSL Client Cached GET", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequest("GET", getUrl, nil)
			resp, err := osslClient.Transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var body map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&body)
			if err != nil {
				b.Fatalf("Invalid JSON response: %v", err)
			}
		}
	})

	b.Run("Custom OSSL Client Cached POST", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			payload := []byte(`{"key": "value"}`)
			req, _ := http.NewRequest("POST", postUrl, bytes.NewBuffer(payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := osslClient.Transport.RoundTrip(req)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()
		}
	})

	b.Run("Custom OSSL Client Cached MIXED", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if rand.Intn(2) == 0 {
				req, _ := http.NewRequest("GET", getUrl, nil)
				resp, err := osslClient.Transport.RoundTrip(req)
				if err != nil {
					b.Fatalf("GET request failed: %v", err)
				}
				defer resp.Body.Close()

				var body map[string]interface{}
				err = json.NewDecoder(resp.Body).Decode(&body)
				if err != nil {
					b.Fatalf("Invalid JSON response: %v", err)
				}
			} else {
				payload := []byte(`{"key": "value"}`)
				req, _ := http.NewRequest("POST", postUrl, bytes.NewBuffer(payload))
				req.Header.Set("Content-Type", "application/json")
				resp, err := osslClient.Transport.RoundTrip(req)
				if err != nil {
					b.Fatalf("POST request failed: %v", err)
				}
				defer resp.Body.Close()
			}
		}
	})
}

func BenchmarkClientDefault(b *testing.B) {
	stdClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{},
		},
	}

	b.Run("Standard HTTP Client GET", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			resp, err := stdClient.Get(getUrl)
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			var body map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&body)
			if err != nil {
				b.Fatalf("Invalid JSON response: %v", err)
			}
		}
	})

	b.Run("Standard HTTP Client POST", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			payload := []byte(`{"key": "value"}`)
			resp, err := stdClient.Post(postUrl, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				b.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()
		}
	})

	b.Run("Standard HTTP Client MIXED", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if rand.Intn(2) == 0 {
				resp, err := stdClient.Get(getUrl)
				if err != nil {
					b.Fatalf("GET request failed: %v", err)
				}
				defer resp.Body.Close()

				var body map[string]interface{}
				err = json.NewDecoder(resp.Body).Decode(&body)
				if err != nil {
					b.Fatalf("Invalid JSON response: %v", err)
				}
			} else {
				payload := []byte(`{"key": "value"}`)
				resp, err := stdClient.Post(postUrl, "application/json", bytes.NewBuffer(payload))
				if err != nil {
					b.Fatalf("POST request failed: %v", err)
				}
				defer resp.Body.Close()
			}
		}
	})
}
