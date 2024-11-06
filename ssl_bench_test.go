package client_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/url"
	"testing"

	ossl "github.com/golang-fips/openssl/v2"
)

const URL = "https://httpbingo.org/"

var (
	postUrl, _ = url.JoinPath(URL, "post")
	getUrl, _  = url.JoinPath(URL, "get")
)

func init() {
	if err := ossl.Init(""); err != nil {
		panic(err)
	}
}

func BenchmarkClientSSL(b *testing.B) {
	osslClient, err := ossl.NewClient()
	if err != nil {
		b.Fatal(err)
	}
	defer osslClient.Close()
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
