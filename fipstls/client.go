package fipstls

import (
	"net/http"
)

// NewClient returns an [http.Client] with [Transport] that uses [Dialer] to
// create [Conn] connections configured by [Config].
func NewClient(tls *Config, opts ...DialOption) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Dialer: NewDialer(tls, opts...),
		},
	}
}
