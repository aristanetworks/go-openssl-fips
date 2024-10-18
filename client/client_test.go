package client_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-fips/openssl/v2/client"
)

type Item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ItemStore struct {
	items map[string]Item
}

func NewItemStore() *ItemStore {
	return &ItemStore{
		items: make(map[string]Item),
	}
}

func (s *ItemStore) GetItem(id string) (Item, bool) {
	item, ok := s.items[id]
	return item, ok
}

func (s *ItemStore) SetItem(item Item) {
	s.items[item.ID] = item
}

type testServer struct {
	server *httptest.Server
	store  *ItemStore
}

func newTestServer() *testServer {
	store := NewItemStore()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		item, ok := store.GetItem(id)
		if !ok {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(item)
	})

	mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
		var item Item
		err := json.NewDecoder(r.Body).Decode(&item)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.SetItem(item)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(item)
	})

	mux.HandleFunc("/status/{code}", func(w http.ResponseWriter, r *http.Request) {
		code := r.PathValue("code")
		statusCode := http.StatusOK
		if code == "404" {
			statusCode = http.StatusNotFound
		}
		w.WriteHeader(statusCode)
	})

	server := httptest.NewTLSServer(mux)

	return &testServer{
		server: server,
		store:  store,
	}
}

func (ts *testServer) Close() {
	ts.server.Close()
}

func TestSSLClientGet(t *testing.T) {
	ts := newTestServer()
	defer ts.Close()

	sslClient, err := client.NewSSLClient(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{"Get Item", "/items/1", http.StatusOK},
		{"Not Found", "/status/404", http.StatusNotFound},
	}

	ts.store.SetItem(Item{ID: "1", Name: "Test Item"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := sslClient.Get(ts.server.URL + tt.path)
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
	ts := newTestServer()
	defer ts.Close()

	sslClient, err := client.NewSSLClient(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Create Item", func(t *testing.T) {
		newItem := Item{ID: "2", Name: "New Item"}
		jsonData, _ := json.Marshal(newItem)

		resp, err := sslClient.Post(ts.server.URL+"/items", "application/json",
			strings.NewReader(string(jsonData)))
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			t.Errorf("Expected status %d, got %d", http.StatusCreated, resp.StatusCode)
		}

		var createdItem Item
		err = json.NewDecoder(resp.Body).Decode(&createdItem)
		if err != nil {
			t.Fatalf("Failed to decode response body: %v", err)
		}

		if createdItem != newItem {
			t.Errorf("Created item doesn't match: expected %v, got %v", newItem, createdItem)
		}
	})
}
