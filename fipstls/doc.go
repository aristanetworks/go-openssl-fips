// Package fipstls implements TLS client methods using OpenSSL shared libraries and cgo.
// When configured correctly, OpenSSL can be executed in FIPS mode, making the fipstls package
// FIPS compliant.
//
// Prior to using any fipstls methods, the [Init] method must be called to dynamically
// load libssl. If that fails, then the program has the option to handle the error and fallback to
// default go/crypto.

// There are three structs that the caller may use in creating TLS connections:
//   - The [Config] struct is used for configuring TLS options for the [Context].
//   - The [Dialer] creates a [Context] for every new [Conn] connection. The [Conn] connection is
//     responsible for freeing the C memory allocated by OpenSSL when
//     it is closed.
//   - The [Transport] calls into the [Dialer] for creating a new TLS connection
//     every roundtrip.
package fipstls
