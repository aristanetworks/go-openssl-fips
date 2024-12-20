// Package fipstls implements TLS client methods using OpenSSL shared libraries and cgo.
// When configured correctly, OpenSSL can be executed in FIPS mode, making the fipstls package
// FIPS compliant.
//
// The [SSLContext] must be configured before the client or [Dialer] can be used. The SSLContext is
// responsible for initializing libssl and the TLS [Config] that will be used to
// create [SSL] connections.
//
// There are two options initializing the [SSLContext],
//   - [NewCtx] will initialize the C.SSL_CTX with TLS configuration options only, but
//     not create the underlying C.SSL_CTX object. Instead, the [Dialer] will create and
//     cleanup the C.SSL_CTX every new [SSL] connection.
//   - [NewUnsafeCtx] will both initialize and create the underlying C.SSL_CTX object once, and
//     the [Dialer] will reuse it in creating multiple [SSL] connections.
//
// Creating the context once and reusing it is considered best practice by OpenSSL developers, as
// internally to OpenSSL various items are shared between multiple SSL objects are cached in in
// the C.SSL_CTX. The drawback is that the caller will be responsible for closing the context
// which will cleanup the C memory allocated for it.
package fipstls
