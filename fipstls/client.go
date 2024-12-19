// The `fipstls“ package implements TLS client methods using OpenSSL shared libraries and cgo.
// When configured correctly, OpenSSL can be executed in FIPS mode, making the `fipstls` package
// FIPS compliant.

package fipstls

import (
	"net/http"
)

// NewClient returns an [http.Client] with [Transport] that uses [Dialer] to
// create [SSL] connections configured by [SSLContext]. The [SSLContext] should
// not be nil.
//
// If the supplied [SSLContext] was created with [NewCtx], then a new context will
// be created every RoundTrip. The caller does not need to worry about explictly
// freeing C memory allocated by the [SSLContext].
//
// If the supplied [SSLContext] was created with [NewReusableCtx], then it is
// created once and and reused across [SSL] dials by the [Dialer]. It is the
// caller's responsibility to close the context with [SSLContext.Close]. Closing the
// context will free the C memory allocated by it.
func NewClient(c *SSLContext, opts ...DialerOption) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Dialer: NewDialer(c, opts...),
		},
	}
}
