# Go OpenSSL TLS Client

[![Go Reference](https://pkg.go.dev/badge/github.com/aristanetworks/go-openssl-fips/ossl.svg)](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/ossl)

The `ossl` package implements TLS client methods using OpenSSL shared libraries and cgo. When configured correctly, OpenSSL can be executed in FIPS mode, making the `ossl` package FIPS compliant.

The `ossl` package is designed to be used as a drop-in replacement for:
- [http.Client](https://pkg.go.dev/net/http#Client)
- [grpc.WithContextDialer](https://pkg.go.dev/google.golang.org/grpc#WithContextDialer)

## Disclaimer

A program directly or indirectly using this package in FIPS mode can claim it is using a FIPS-certified cryptographic module (OpenSSL), but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

## Features

### Multiple OpenSSL versions supported

The `ossl` package has support for multiple OpenSSL versions, namely 1.1.1 and 3.x.

All supported OpenSSL versions pass a set of automatic tests that ensure they can be built and that there are no major regressions.
These tests do not validate the cryptographic correctness of the `ossl` package.

### Graceful Exit

The `ossl.Init` method dynamically loads the `libssl.so` library. This doesn't need to be managed by the caller as the `libssl.so` library will be dynamically loaded before any calls into OpenSSL.

If the `ossl` package cannot dynamically load the `libssl.so` library, it will gracefully exit with:
```
ossl: libssl failed to load
```

### Building without OpenSSL headers

The `ossl` package does not use any symbol from the OpenSSL headers. There is no need that have them installed to build an application which imports this library.

### Portable OpenSSL

The OpenSSL bindings are implemented in such a way that the OpenSSL version available when building a program does not have to match with the OpenSSL version used when running it.
In fact, OpenSSL doesn't need to be present on the builder.
For example, using the `ossl` package and `go build .` on a Windows host with `GOOS=linux` can produce a program that successfully runs on Linux and uses OpenSSL.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain that integrates the `ossl` package.

## Limitations

- Only Unix, Unix-like and Windows platforms are supported.
- The build must set `CGO_ENABLED=1`.

## Benchmarks

Some benchmark results comparing the `ossl.Client` to `http.Client`. The server used in the tests is httpbingo.org.
```
> go test -bench "BenchmarkClientSSL*" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/ossl
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  27          45898493 ns/op           84971 B/op        233 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30          40696457 ns/op           86030 B/op        171 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                31          43308677 ns/op           94426 B/op        202 allocs/op
PASS
ok      github.com/aristanetworks/go-openssl-fips/ossl       5.408s
```

```
> go test -bench "BenchmarkClientDefault*" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/ossl
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientDefault/Standard_HTTP_Client_GET-96                    51          23254395 ns/op           56392 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96                   51          40406477 ns/op          148356 B/op        941 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96                  38          30623265 ns/op           99794 B/op        500 allocs/op
PASS
ok      github.com/aristanetworks/go-openssl-fips/ossl       5.861s
```

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- The [golang-fips](https://github.com/golang-fips/openssl/tree/v2) shim layer of Red Hat's fork of [golang](https://github.com/golang-fips/go).
- The portable OpenSSL implementation is ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Code of Conduct

This project adopts the Go code of conduct: https://go.dev/conduct.
