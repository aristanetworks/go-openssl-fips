// Package fipstls implements TLS client methods using OpenSSL shared libraries and cgo.
// When configured correctly, OpenSSL can be executed in FIPS mode, making the `fipstls` package
// FIPS compliant.
//
// If the supplied [SSLContext] was created with [NewCtx], then a new context will
// be created every [Dialer.DialContext]. The caller does not need to worry about explictly
// freeing C memory allocated for the [SSLContext].
//
// If the supplied [SSLContext] was created with [NewUnsafeCtx], then it is
// created once and and reused across [SSL] dials by the [Dialer]. It is the
// caller's responsibility to close the context with [SSLContext.Close].

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
