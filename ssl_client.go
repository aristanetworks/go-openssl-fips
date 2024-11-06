package client

import (
	"net/http"
	"sync"
)

// Client is an [http.Client] that manages the lifetime of the [SSLContext] which is used to create
// [SSL] connections by [SSLConn].
type Client struct {
	http.Client
	ctx       *SSLContext
	closeOnce sync.Once
}

// NewClient returns a new [http.Client] using a [SSLDialer.DialTLSContext] to call into dynamically loaded
// libssl on the host.
func NewClient(opts ...ConfigOption) (*Client, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
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
		Transport: &http.Transport{
			DialTLSContext: d.DialTLSContext,
		},
	}
	return &Client{Client: client, ctx: ctx}, nil
}

// Close will free the [SSLContext] used to create [SSL] connections
// WARNING: use CloseIdleConnections() only if you are sure all idle connections
// are unused
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.ctx.Free()
	})
}
