package fipstls_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

// func TestDialConn(t *testing.T) {
// 	defer testutils.LeakCheckLSAN(t)
// 	ts := testutils.NewTestServer(t)
// 	defer ts.Close()

// 	u, err := url.Parse(ts.URL)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	host, port, err := net.SplitHostPort(u.Host)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	d := fipstls.NewDialer(
// 		fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
// 		fipstls.WithConnTracingEnabled(),
// 	)
// 	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
// 	if err != nil {
// 		t.Fatalf("Failed to create SSLConn: %v", err)
// 	}
// 	defer conn.Close()

// 	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
// 	_, err = conn.Write([]byte(request))
// 	if err != nil {
// 		t.Fatalf("Failed to write request: %v", err)
// 	}

// 	reader := bufio.NewReader(conn)
// 	response, err := reader.ReadString('\n')
// 	if err != nil {
// 		t.Fatalf("Failed to read response: %v", err)
// 	}

// 	if !strings.Contains(string(response), "HTTP/1.1") {
// 		t.Errorf("Unexpected response: %s", response)
// 	}
// 	fmt.Printf("Response: %s\n", string(response))
// }

// func TestDialDeadline(t *testing.T) {
// 	defer testutils.LeakCheckLSAN(t)
// 	ts := testutils.NewTestServer(t)
// 	defer ts.Close()

// 	u, err := url.Parse(ts.URL)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	host, port, err := net.SplitHostPort(u.Host)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	d := fipstls.NewDialer(
// 		fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
// 		fipstls.WithConnTracingEnabled(),
// 	)
// 	conn, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
// 	if err != nil {
// 		t.Fatalf("Failed to create SSLConn: %v", err)
// 	}
// 	defer conn.Close()

// 	conn.SetDeadline(time.Now().Add(2 * time.Second))
// 	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", host)
// 	_, err = conn.Write([]byte(request))
// 	if err != nil {
// 		t.Fatalf("Failed to write request: %v", err)
// 	}
// 	time.Sleep(3 * time.Second)

// 	reader := bufio.NewReader(conn)
// 	_, err = reader.ReadString('\n')
// 	if err == nil {
// 		t.Fatal("Deadline should have been reached")
// 	} else if errors.Is(err, os.ErrDeadlineExceeded) {
// 		t.Logf("Deadline reached as expected with err %v", err)
// 	} else {
// 		t.Fatalf("Error is not deadline error: %v", err)
// 	}
// }

func TestDialTimeout(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)
	// Create and start the server directly
	ts := testutils.NewServer(t)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := fipstls.NewDialer(
		fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
		fipstls.WithConnTracingEnabled(),
	)

	conn, err := d.DialContext(context.Background(), "tcp", u.Host)
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	tests := []struct {
		name          string
		writeDeadline time.Duration
		readDeadline  time.Duration
		serverDelay   time.Duration
		wantErr       error
		checkResponse bool
	}{
		{
			name:          "basic connection",
			checkResponse: true,
		},
		{
			name:          "read deadline exceeded",
			readDeadline:  400 * time.Millisecond,
			wantErr:       os.ErrDeadlineExceeded,
			checkResponse: false,
		},
		{
			name:          "write deadline exceeded",
			writeDeadline: 400 * time.Millisecond,
			wantErr:       os.ErrDeadlineExceeded,
			checkResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// default request
			request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host)
			// For read timeout tests, send a GET that will sleep
			if tt.readDeadline > 0 {
				conn.SetReadDeadline(time.Now().Add(tt.readDeadline))
				request = fmt.Sprintf("GET /sleep/%d HTTP/1.1\r\nHost: %s\r\n\r\n",
					tt.readDeadline.Milliseconds()*2, u.Host)
			}
			// For write tests, sleep before completing the write
			if tt.writeDeadline > 0 {
				conn.SetReadDeadline(time.Now().Add(tt.writeDeadline))
				// Write first half of request
				if _, err := conn.Write([]byte(request[:len(request)/2])); err != nil {
					t.Fatalf("Failed to write first half: %v", err)
				}
				// Sleep to trigger deadline
				time.Sleep(tt.writeDeadline * 2)
				// Try to write second half
				request = request[len(request)/2:]
			}

			_, err = conn.Write([]byte(request))
			if err != nil {
				if tt.wantErr != nil {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("Write error = %v, want %v", err, tt.wantErr)
					}
					return
				}
				t.Fatalf("Failed to write request: %v", err)
			}

			reader := bufio.NewReader(conn)
			response, err := reader.ReadString('\n')

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("Expected an error but got none")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Read error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if tt.checkResponse {
				if err != nil {
					t.Fatalf("Failed to read response: %v", err)
				}
				if !strings.Contains(response, "HTTP/1.1") {
					t.Errorf("Unexpected response: %s", response)
				}
				t.Logf("Response: %s", response)
			}
		})
	}
}

func TestDialNilContext(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic with nil context, but got none")
		}
	}()

	// This should panic
	fipstls.NewDialer(
		nil,
		fipstls.WithConnTracingEnabled(),
	)
	t.Error("Expected panic, but function returned normally")
}
