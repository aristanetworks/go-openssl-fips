package fipstls

import (
	"net/http"
)

// NewClient returns an [http.Client] with [Transport] that uses [Dialer] to
// create [Conn] connections configured by [Context]. The [Context] should
// not be nil.
func NewClient(c *Context, opts ...DialOption) (*http.Client, error) {
	d, err := NewDialer(c, opts...)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &Transport{
			Dialer: d,
		},
	}, nil
}
