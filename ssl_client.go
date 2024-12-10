package ossl

import (
	"net/http"
)

// Client is an [http.Client] that stores the [SSLContext] which is used to create
// [SSL] connections by [Conn]. The caller is responsible for freeing the C memory allocated by
// the [SSLContext] with [Client.Close].
type Client struct {
	http.Client
	// Ctx is the [SSLContext] used for creating [SSL] connections.
	Ctx *SSLContext
}

// NewClient returns a new [http.Client] using [Dialer.Dial] to call into dynamically the
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
	return &Client{Client: client, Ctx: ctx}, nil
}

// Close will free the [SSLContext] used to create [SSL] connections.
func (c *Client) Close() error {
	return c.Ctx.Free()
}
