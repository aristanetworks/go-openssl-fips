// Package fipstls implements TLS client methods using OpenSSL shared libraries and cgo.
// When configured correctly, OpenSSL can be executed in FIPS mode, making the fipstls package
// FIPS compliant.
//
// Prior to using any `fipstls` methods, the [`fipstls.Init`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Init) method must be called to dynamically load libssl. If that fails, then the program has the option to handle the error and fallback to default go/crypto.

// There are three structs that the caller may use in creating TLS connections:
// - The [`fipstls.Config`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Config) struct is used for configuring TLS options for the [`fipstls.Context`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Context).
// - The [`fipstls.Dialer`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Dialer) creates a [`fipstls.Context`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Context) for every new [`fipstls.Conn`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Conn) connection. The [`fipstls.Conn`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Conn) connection is responsible for freeing the C memory allocated by OpenSSL when it is closed.
// - The [`fipstls.Transport`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Transport) calls into the [`fipstls.Dialer`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Dialer) for creating a new TLS connection every roundtrip.
package fipstls
