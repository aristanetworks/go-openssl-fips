package fipstls

import (
	"net/http"
)

// NewDefaultClient returns an [http.Client] with a [Transport]. The context
// is not cached and will be re-created every RoundTrip.
//
// The caller does not need to worry about explictly freeing C memory allocated
// by the [Context].
func NewDefaultClient(opts ...ConfigOption) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Dialer: &Dialer{Ctx: NewCtx(opts...)},
		},
	}
}

// NewClientWithCachedCtx returns an [http.Client] with [Transport] initialized by
// a context that will be reused across [SSL] dials by the [Dialer].
//
// It is the caller's responsibility to close the context with [Context.Close].
// Closing the context will free the C memory allocated by it.
func NewClientWithCachedCtx(opts ...ConfigOption) (*http.Client, *Context, error) {
	ctx, err := NewCachedCtx(opts...)
	if err != nil {
		return nil, nil, err
	}
	return &http.Client{
		Transport: &Transport{
			Dialer: &Dialer{Ctx: ctx},
		},
	}, ctx, nil
}
