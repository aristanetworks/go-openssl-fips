package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
