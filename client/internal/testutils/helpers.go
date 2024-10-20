package testutils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Server represents a test HTTPS server.
type Server struct {
	*httptest.Server
	URL string // URL of the test server
}

// NewServer creates a new test HTTPS server.
func NewServer(t *testing.T) *Server {
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

		// Check Content-Type header
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
			return
		}

		// Read request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Set Content-Type header for response
		w.Header().Set("Content-Type", "application/json")

		// Return the received JSON in the response
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})

	mux.HandleFunc("/put", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Received PUT request with body: %s", string(body))))
	})

	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		response := map[string]string{"message": "This is a GET response"}
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/status/{code}", func(w http.ResponseWriter, r *http.Request) {
		codeStr := r.URL.Path[len("/status/"):]
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			http.Error(w, "Invalid status code", http.StatusBadRequest)
			return
		}
		w.WriteHeader(code)
	})

    server := httptest.NewUnstartedServer(mux)
    server.StartTLS()
	return &Server{
		Server: server,
		URL:    server.URL,
	}
}
