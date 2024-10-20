package client

import (
	"net/http"
	"time"

	"github.com/golang-fips/openssl/v2/libssl"
)

// NewSSLClient returns a new http.Client using an SSLTransport to call into dynamically loaded
// libssl on the host.
func NewSSLClient(timeout time.Duration) (*http.Client, error) {
	// dynamically load the libssl library
	err := libssl.Init(libssl.Version)
	if err != nil {
		// fallback to default http.Client
		return &http.Client{Timeout: timeout}, err
	}

	return &http.Client{
		Transport: &SSLTransport{Timeout: timeout},
	}, nil
}
