package fipstls

import (
	"net/http"
)

// NewClient returns an [http.Client] with [Transport] that uses [Dialer] to
// create [SSL] connections configured by [SSLContext]. The [SSLContext] should
// not be nil.
func NewClient(c *SSLContext, opts ...DialerOption) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Dialer: NewDialer(c, opts...),
		},
	}
}
