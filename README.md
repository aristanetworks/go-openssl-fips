# Go OpenSSL FIPS TLS Client

[![Go Reference](https://pkg.go.dev/badge/github.com/aristanetworks/go-openssl-fips/fipstls.svg)](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls)

The `fipstls` package implements TLS client methods using OpenSSL shared libraries and cgo. When configured correctly, OpenSSL can be executed in FIPS mode, making the `fipstls` package FIPS compliant.

The `fipstls` package is designed to be used as a drop-in replacement for:
- [http.Client](https://pkg.go.dev/net/http#Client)
- [grpc.WithContextDialer](https://pkg.go.dev/google.golang.org/grpc#WithContextDialer)

## Disclaimer

A program directly or indirectly using this package in FIPS mode can claim it is using a FIPS-certified cryptographic module (OpenSSL), but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Background

FIPS 140-2 is a U.S. government computer security standard used to approve cryptographic modules. FIPS compliance may come up when working with U.S. government and other regulated industries.

## Features

### Multiple OpenSSL versions supported

The `fipstls` package has support for multiple OpenSSL versions, namely 1.1.1 and 3.x.

All supported OpenSSL versions pass a set of automatic tests that ensure they can be built and that there are no major regressions.
These tests do not validate the cryptographic correctness of the `fipstls` package.

### Graceful Exit

The `fipstls.Init` method dynamically loads the `libssl.so` library. This doesn't need to be managed by the caller as the `libssl.so` library will be dynamically loaded before any calls into OpenSSL.

If the `fipstls` package cannot dynamically load the `libssl.so` library, it will gracefully exit with:
```
fipstls: libssl failed to load
```

### Building without OpenSSL headers

The `fipstls` package does not use any symbol from the OpenSSL headers. There is no need that have them installed to build an application which imports this library.

### Portable OpenSSL

The OpenSSL bindings are implemented in such a way that the OpenSSL version available when building a program does not have to match with the OpenSSL version used when running it.
In fact, OpenSSL doesn't need to be present on the builder.
For example, using the `fipstls` package and `go build .` on a Windows host with `GOOS=linux` can produce a program that successfully runs on Linux and uses OpenSSL.

This feature does not require any additional configuration, but it only works with OpenSSL versions known and supported by the Go toolchain that integrates the `fipstls` package.

## Limitations

- Only Unix, Unix-like and Windows platforms are supported.
- The build must set `CGO_ENABLED=1`.

## Examples

The `fipstls.SSLContext` must be configured before the client or dialer can be used. The `fipstls.SSLContext` is responsible for initializing libssl and TLS configuration that will be used to create `fipstls.SSL` connections.

There are two options initializing the `fipstls.SSLContext`:
- [`fipstls.NewCtx`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#NewCtx) - this will initialize the `fipstls.SSLContext` with TLS configuration options only, but not create the underlying `libssl.SSLCtx` C object. Instead, the `fipstls.Dialer` will create and cleanup the `libssl.SSLCtx` every new `fipstls.SSL` connection.
- [`fipstls.NewUnsafeCtx`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#NewUnsafeCtx) - this will both initialize and create the underlying `libssl.SSLCtx` C object once, and the `fipstls.Dialer` will reuse it in creating multiple `fipstls.SSL` connections.

Creating the context once and reusing it is considered best practice by OpenSSL developers, as internally to OpenSSL various items are shared between multiple SSL objects are cached in in the SSL_CTX. The drawback is that the caller will be responsible for closing the context which will cleanup the C memory allocated by it.

### 1. Creating a Default Client

This example demonstrates how to create a default `http.Client` with TLS configured using `NewDefaultClient`. The underlying `libssl.SSLCtx` is managed by the `Dialer` and recreated for each roundtrip.

```go
import (
	"fmt"
	"net/http"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
)

func main() {
	// Create a default client with TLS configured for TLS 1.3
	sslCtx := fipstls.NewCtx(
		fipstls.WithCaFile("/path/to/cert.pem"),
		fipstls.WithMinTLSVersion(fipstls.Version13))
	client := fiptls.NewClient(sslCtx)

	// Use the client to make HTTPS requests
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// ... process the response ...
}
```

### 2. Creating a Client with a Reusable Context

This example demonstrates how to create an `http.Client` with a reuseable `fipstls.SSLContext` using `NewUnsafeCtx`. This creates the `fipstls.SSLContext` once and allows the `libssl.SSLCtx` to be reused across multiple roundtrips, improving performance.

```go
import (
	"fmt"
	"net/http"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
)

func main() {
	// Create a client with an unsafe, reusable Context
	ctx, err := fipstls.NewUnsafeCtx()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer ctx.Close() // Close the Context when done

	client := fipstls.NewClient(ctx)
	// Use the client to make HTTPS requests
	_, err = client.Get("https://example.com")
	// ...

	_, err = client.Get("https://another.example.com")
	// ...
}
```

**Note:** In the case of `NewUnsafeCtx`, it's the caller's responsibility to close the `fiptls.SSLContext` using `fiptls.SSLContext.Close` when it's no longer needed. This will free the associated C memory.

### 3. Creating a Default Dialer

This example demonstrates how to create a default `Dialer` with default options using `NewCtx`. The underlying `libssl.SSLCtx` is managed by the `Dialer`.

``` go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"google.golang.org/grpc"
)

func main() {
	// Create an fipstls.Dialer with the configured context
	dialFn := fiptls.NewGrpcDialFn(
		fipstls.NewCtx(fipstls.WithCaFile("/path/to/cert.pem")),
		fipstls.WithTimeout(10 * time.Second))

	// Use grpc.WithContextDialer to create a gRPC connection that will create
	// a new Context every dial
	conn, err := grpc.DialContext(
		context.Background(),
		"your-grpc-server-address:port",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialFn),
	)
	if err != nil {
		log.Fatalf("Failed to dial gRPC server: %v", err)
	}
	// this will free the C memory allocated by the context
	defer conn.Close()

	// ... use the gRPC connection ...
}
```

### 4. Creating a Dialer with a Reusable Context

This example demonstrates how to create a `Dialer` with a unsafe, reusable `fipstls.SSLContext` using `NewUnsafeCtx`. This creates the `fipstls.SSLContext` once and allows the `libssl.SSLCtx` to be reused across multiple roundtrips, improving performance.
``` go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"google.golang.org/grpc"
)

func main() {
	// Create an fipstls.Dialer with an unsafe, reusable context
	ctx, err := fipstls.NewUnsafeCtx(fipstls.WithCaFile("/path/to/cert.pem"))
	if err != nil {
		log.Fatalf("Failed to create context: %v", err)
	}
	// this will free the C memory allocated by the context
	defer ctx.Close()
	fipsDialFn := fiptls.NewGrpcDialFn(ctx, "tcp", fipstls.WithTimeout(10 * time.Second))

	// Use grpc.WithContextDialer to create a gRPC connection that will reuse
	// the context to create SSL connections.
	conn, err := grpc.DialContext(
		context.Background(),
		"your-grpc-server-address:port",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(fipsDialFn),
	)
	if err != nil {
		log.Fatalf("Failed to dial gRPC server: %v", err)
	}
	defer conn.Close()

	// ... use the gRPC connection ...
}
```

**Note:** In the case of `NewUnsafeCtx`, it's the caller's responsibility to close the `fiptls.SSLContext` using `fiptls.SSLContext.Close` when it's no longer needed. This will free the associated C memory.

## Benchmarks

Some benchmark results comparing the `fipstls.Client` to `http.Client`. The server used in the tests is httpbingo.org.
```
> go test -bench "BenchmarkClientSSL*" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  14          97719506 ns/op           88790 B/op        253 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 14         450657159 ns/op           91713 B/op        191 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                15         105323361 ns/op           91306 B/op        220 allocs/op
PASS
ok      github.com/aristanetworks/go-openssl-fips/fipstls  11.497s
```

```
> go test -bench "BenchmarkClientCachedSSL*" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientCachedSSL/Custom_OSSL_Client_Cached_GET-96                     30          46490736 ns/op           88611 B/op        251 allocs/op
BenchmarkClientCachedSSL/Custom_OSSL_Client_Cached_POST-96                    28          40520187 ns/op           88877 B/op        186 allocs/op
BenchmarkClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96                   31          43065017 ns/op           92676 B/op        223 allocs/op
PASS
ok      github.com/aristanetworks/go-openssl-fips/fipstls  4.580s
```

```
> go test -bench "BenchmarkClientDefault*" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientDefault/Standard_HTTP_Client_GET-96                    51          23254395 ns/op           56392 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96                   51          40406477 ns/op          148356 B/op        941 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96                  38          30623265 ns/op           99794 B/op        500 allocs/op
PASS
ok      github.com/aristanetworks/go-openssl-fips/fipstls       5.861s
```

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- The [golang-fips](https://github.com/golang-fips/openssl/tree/v2) shim layer of Red Hat's fork of [golang](https://github.com/golang-fips/go).
- The portable OpenSSL implementation is ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Code of Conduct

This project adopts the Go code of conduct: https://go.dev/conduct.
