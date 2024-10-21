package client

import (
	"net/http"
	"time"

	"github.com/golang-fips/openssl/v2/client/conn"
	"github.com/golang-fips/openssl/v2/libssl"
)

// NewSSLClient returns a new http.Client using an SSLTransport to call into dynamically loaded
// libssl on the host.
func NewSSLClient(version string, timeout time.Duration, config *conn.Config) (*http.Client, error) {
	// dynamically load the libssl library
	if version == "" {
		version = libssl.GetVersion()
	}
	err := libssl.Init(version)
	if err != nil {
		// fallback to default http.Client
		return &http.Client{Timeout: timeout}, err
	}

	return &http.Client{
		Transport: &SSLTransport{Timeout: timeout, Config: config},
	}, nil
}
