package ossl

import (
	"net/http"
)

// NewClient returns an [http.Client] with [SSL] transport.
func NewClient(ctx *Context, opts ...TLSOption) *http.Client {
	if ctx == nil {
		ctx = NewDefaultTLSContext(opts...)
	}
	return &http.Client{
		Transport: &Transport{
			Dialer: NewDialer(ctx),
		},
	}
}

// NewTLSClient returns an [http.Client] with [SSL] transport.
func NewTLSClient(opts ...TLSOption) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Dialer: NewDialer(NewDefaultTLSContext(opts...)),
		},
	}
}
