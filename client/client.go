package client

import (
	"net/http"

	"github.com/golang-fips/openssl/v2/libssl"
)

// New returns a new http.Client using an SSLTransport to call into dynamically loaded
// libssl on the host.
func New(version string, opts... TransportOption) (*http.Client, error) {
	// dynamically load the libssl library
	if version == "" {
		version = libssl.GetVersion()
	}
	err := libssl.Init(version)
	if err != nil {
		return nil, err
	}

	t := &SSLTransport{}
	for _, o := range opts {
		o(t)
	}
	return &http.Client{
		Transport: t,
	}, nil
}
