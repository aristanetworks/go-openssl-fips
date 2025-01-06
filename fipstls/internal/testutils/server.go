package testutils

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServer is a test HTTPS server with tracing.
type TestServer struct {
	t testing.TB
	*httptest.Server
	URL    string
	CaFile string
}

var (
	//go:embed certs/cert.pem
	certBytes []byte

	//go:embed certs/key.pem
	keyBytes []byte

	caFile, _ = filepath.Abs("internal/testutils/certs/cert.pem")

	// Certificate parsing is done once at init
	serverCert tls.Certificate
	createOnce sync.Once
	certErr    error
)

func init() {
	createOnce.Do(func() {
		serverCert, certErr = tls.X509KeyPair(certBytes, keyBytes)
	})
}

// TestListener wraps net.Listener to trace accept events
type TestListener struct {
	net.Listener
	t testing.TB
}

func (l *TestListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		l.t.Logf("[Server] Accept error: %v", err)
		return conn, err
	}

	l.t.Logf("[Server] Accepted connection from: %v", conn.RemoteAddr())
	return &TestConn{Conn: conn, t: l.t}, nil
}

// TestConn wraps net.Conn to trace connection events
type TestConn struct {
	net.Conn
	t testing.TB
}

func (c *TestConn) Read(b []byte) (n int, err error) {
	c.t.Logf("[Server] Read from %v begin...", c.Conn.RemoteAddr())
	defer c.t.Logf("[Server] Read from %v end...", c.Conn.RemoteAddr())
	c.t.Logf("[Server] Attempting to read %v bytes", len(b))
	n, err = c.Conn.Read(b)
	if err != nil && err.Error() != "EOF" {
		c.t.Logf("[Server] Read error from %v: %v", c.Conn.RemoteAddr(), err)
	}
	return n, err
}

func (c *TestConn) Write(b []byte) (n int, err error) {
	c.t.Logf("[Server] Write to %v begin...", c.Conn.RemoteAddr())
	defer c.t.Logf("[Server] Write to %v end...", c.Conn.RemoteAddr())
	c.t.Logf("[Server] Attempting to write %v bytes", len(b))
	n, err = c.Conn.Write(b)
	if err != nil {
		c.t.Logf("[Server] Write error to %v: %v", c.Conn.RemoteAddr(), err)
	}
	return n, err
}

func (c *TestConn) Close() error {
	c.t.Logf("[Server] Close of %v begin...", c.Conn.RemoteAddr())
	defer c.t.Logf("[Server] Close of %v end...", c.Conn.RemoteAddr())
	c.t.Logf("[Server] Closing connection from: %v", c.Conn.RemoteAddr())
	return c.Conn.Close()
}

// tracingHandler wraps an http.Handler with tracing.
func tracingHandler(trace testing.TB, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace.Logf("[Server] Handling %s request to %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		trace.Logf("[Server] Request headers: %v", r.Header)

		start := time.Now()
		handler.ServeHTTP(w, r)
		duration := time.Since(start)

		trace.Logf("[Server] Completed %s %s in %v", r.Method, r.URL.Path, duration)
	})
}

type noopTB struct {
	testing.TB
}

func (noopTB) Logf(format string, args ...any) {}

// NewServer creates a new test HTTPS server with tracing.
func NewServer(t testing.TB, trace bool) *TestServer {
	if certErr != nil {
		t.Fatal(certErr)
	}
	if !trace {
		t = noopTB{}
	}
	ts := &TestServer{t: t}

	mux := http.NewServeMux()

	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{"message": "Hello, from a simple HTTPS server!"}
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		response := map[string]string{"message": "This is a GET response"}
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/sleep/", func(w http.ResponseWriter, r *http.Request) {
		// Extract sleep duration from path
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 3 {
			http.Error(w, "Invalid sleep duration", http.StatusBadRequest)
			return
		}

		ms, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			http.Error(w, "Invalid sleep duration", http.StatusBadRequest)
			return
		}

		time.Sleep(time.Duration(ms) * time.Millisecond)

		response := map[string]string{"message": "Slept for requested duration"}
		json.NewEncoder(w).Encode(response)
	})

	server := httptest.NewUnstartedServer(tracingHandler(t, mux))
	originalListener := server.Listener
	server.Listener = &TestListener{Listener: originalListener, t: t}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		// Add TLS connection state logging
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			t.Logf("[Server] TLS ClientHello from %v: Version=%x, CipherSuites=%v, ServerName=%s",
				hello.Conn.RemoteAddr(),
				hello.SupportedVersions,
				hello.CipherSuites,
				hello.ServerName)
			return nil, nil
		},
	}

	server.TLS = tlsConfig
	// server.Config.ReadHeaderTimeout = 30 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.IdleTimeout = 10 * time.Second

	// Add connection state logging
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		t.Logf("[Server] Connection %v changed state to: %v", conn.RemoteAddr(), state)
	}

	server.StartTLS()

	ts.Server = server
	ts.URL = server.URL
	ts.CaFile = caFile

	return ts
}
