package ossl

import (
	"net/http"
)

// Client is an [http.Client] that stores the [SSLContext] which is used to create
// [SSL] connections by [Conn].
type Client struct {
	http.Client
	ctx *SSLContext
}

// NewClient returns a new [http.Client] using [Dialer.DialFn] to call into dynamically the
// loaded libssl for [SSL] connections.
func NewClient(opts ...ConfigOption) (*Client, error) {
	config := DefaultConfig()
	for _, o := range opts {
		o(config)
	}
	ctx, err := NewSSLContext(config)
	if err != nil {
		return nil, err
	}
	d := DefaultDialer(ctx, config)
	client := http.Client{
		Transport: &Transport{
			Dialer: d,
		},
	}
	return &Client{Client: client, ctx: ctx}, nil
}

// Close will free the [SSLContext] used to create [SSL] connections
// WARNING: use [http.Client.CloseIdleConnections] only if you are sure all idle connections
// are unused
func (c *Client) Close() error {
	return c.ctx.Free()
}
