package ossl

import (
	"net/http"
)

// NewClientWithClose returns an [http.Client] with [SSL] transport.
func NewClient(ctx *SSLContext, opts ...ConfigOption) (*http.Client, error) {
	c := DefaultConfig()
	for _, o := range opts {
		o(c)
	}
	return &http.Client{
		Timeout: c.Timeout,
		Transport: &Transport{
			DisableCompression: c.TransportCompressionDisabled,
			Dialer:             &Dialer{Ctx: ctx, Timeout: c.Timeout, Config: c},
		},
	}, nil
}
