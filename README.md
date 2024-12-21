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

The [`fipstls.SSLContext`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#SSLContext) must be configured before the client or dialer can be used. The `fipstls.SSLContext` is responsible for initializing libssl and TLS configuration that will be used to create [`fipstls.Conn`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#SSLConn) connections.

There are two options initializing the `fipstls.SSLContext`:
- [`fipstls.NewCtx`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#NewCtx) - this will initialize the `fipstls.SSLContext` with TLS configuration options only, but not create the underlying `C.SSL_CTX` object. Instead, the `fipstls.Dialer` will create and cleanup the `C.SSL_CTX` every new `fipstls.Conn` connection.
- [`fipstls.NewUnsafeCtx`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#NewUnsafeCtx) - this will both initialize and create the underlying `C.SSL_CTX` object once, and the `fipstls.Dialer` will reuse it in creating multiple `fipstls.Conn` connections.

Creating the context once and reusing it is considered best practice by OpenSSL developers, as internally to OpenSSL various items are shared between multiple SSL objects are cached in the C.SSL_CTX. The drawback is that the caller will be responsible for closing the context which will cleanup the C memory allocated for it.

### 1. Creating a Default Client

This example demonstrates how to create a default `http.Client` with TLS configured using [`NewClient`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#NewClient). The underlying `C.SSL_CTX` is managed by the [`Dialer`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Dialer) and recreated for each roundtrip.

```go
import (
	"fmt"
	"net/http"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
)

func main() {
	// Create a default client with TLS configured for TLS 1.3
	client, err := fipstls.NewClient(fipstls.NewCtx(
		fipstls.WithCaFile("/path/to/cert.pem"),
		fipstls.WithMinTLSVersion(fipstls.Version13)))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	// Use the client to make HTTPS requests
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatalf("Failed get request: %v", err)
	}
	defer resp.Body.Close()

	// ... process the response ...
}
```

### 2. Creating a Client with a Reusable Context

This example demonstrates how to create an `http.Client` with an unsafe, reuseable `fipstls.SSLContext` using `NewUnsafeCtx`. This creates the `C.SSL_CTX` once and allows it to be reused across multiple roundtrips, improving performance.

```go
import (
	"fmt"
	"log"
	"net/http"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
)

func main() {
	// Create a client with an unsafe, reusable Context
	ctx, err := fipstls.NewUnsafeCtx()
	if err != nil {
		log.Fatalf("Failed to create context: %v", err)
	}
	defer ctx.Close() // Close the Context when done

	client, err := fipstls.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Use the client to make HTTPS requests
	_, err = client.Get("https://example.com")
	// ...

	_, err = client.Get("https://another.example.com")
	// ...
}
```

**Note:** In the case of `NewUnsafeCtx`, it's the caller's responsibility to close the `fiptls.SSLContext` using `fiptls.SSLContext.Close` when it's no longer needed. This will free the associated C memory.

### 3. Creating a Default Dialer

This example demonstrates how to create a default `Dialer` using `NewCtx`. The underlying `C.SSL_CTX` is managed by the `Dialer`.

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
	dialFn, err := fiptls.NewGrpcDialFn(
		fipstls.NewCtx(fipstls.WithCaFile("/path/to/cert.pem")),
		fipstls.WithTimeout(10 * time.Second))
	if err != nil {
		log.Fatalf("Failed to create grpc dialer: %v", err)
	}

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
	// this will free the C memory allocated for the context
	defer conn.Close()

	// ... use the gRPC connection ...
}
```

### 4. Creating a Dialer with a Reusable Context

This example demonstrates how to create a `Dialer` with an unsafe, reusable `fipstls.SSLContext` using `NewUnsafeCtx`. This creates the `fipstls.SSLContext` once and allows the `libssl.SSLCtx` to be reused across multiple roundtrips, improving performance.
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
	// this will free the C memory allocated for the context
	defer ctx.Close()
	fipsDialFn, err := fiptls.NewGrpcDialFn(ctx, "tcp", fipstls.WithTimeout(10 * time.Second))
	if err != nil {
		log.Fatalf("Failed to create grpc dialer: %v", err)
	}

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

Some benchmark results comparing the `fipstls.Client` to `http.Client`. The server used in the tests is httpbingo.org. Example run:
```
> go test -failfast -count=20 -bench "BenchmarkClientSSL*/MIXED" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          83867458 ns/op          899700 B/op      28019 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                16          87604697 ns/op          904849 B/op      27745 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          87617542 ns/op          889245 B/op      26991 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                15          81588057 ns/op          918214 B/op      28369 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          84004782 ns/op          882894 B/op      27243 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                10         152552246 ns/op          808991 B/op      24474 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                12          98492739 ns/op          826965 B/op      25201 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                12          98320802 ns/op          724451 B/op      21521 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                12          95175290 ns/op          964964 B/op      29649 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13         116746389 ns/op          804663 B/op      24002 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                15          83747989 ns/op          837553 B/op      25312 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          94063913 ns/op          674540 B/op      19814 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          92405464 ns/op          699888 B/op      20557 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                12          86227267 ns/op          768018 B/op      23329 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          90324236 ns/op          894168 B/op      27460 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          95083683 ns/op          771742 B/op      23138 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                14          87884232 ns/op          791622 B/op      23987 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                13          86478534 ns/op          781618 B/op      23899 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                15          90007049 ns/op          801590 B/op      23983 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                14          89964775 ns/op          812952 B/op      24680 allocs/op
PASS
ok      github.com/aristanetworks/go-openssl-fips/fipstls       37.727s
```

### Default SSL Client
____________________
```
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
                                      │ ssl-default │
                                      │   sec/op    │
ClientSSL/Custom_OSSL_Client_MIXED-96   89.99m ± 6%

                                      │  ssl-default  │
                                      │     B/op      │
ClientSSL/Custom_OSSL_Client_MIXED-96   792.0Ki ± 10%

                                      │ ssl-default  │
                                      │  allocs/op   │
ClientSSL/Custom_OSSL_Client_MIXED-96   24.58k ± 11%

```

### "Cached", Unsafe, Reused SSL Client
____________________
```
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
                                                   │ ssl-cached  │
                                                   │   sec/op    │
ClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96   39.84m ± 2%

                                                   │  ssl-cached  │
                                                   │     B/op     │
ClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96   663.1Ki ± 5%

                                                   │ ssl-cached  │
                                                   │  allocs/op  │
ClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96   20.22k ± 5%
```

### Default http.Client
____________________
```
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
                                            │ http-default │
                                            │    sec/op    │
ClientDefault/Standard_HTTP_Client_MIXED-96    33.10m ± 5%

                                            │ http-default │
                                            │     B/op     │
ClientDefault/Standard_HTTP_Client_MIXED-96   102.3Ki ± 4%

                                            │ http-default │
                                            │  allocs/op   │
ClientDefault/Standard_HTTP_Client_MIXED-96     539.5 ± 7%
```

## Benchstat Comparison
Generated with `benchstat http-default ssl-cached ssl-default > compare-benchstat`
```
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
                                                   │ http-default │     ssl-cached     │    ssl-default     │
                                                   │    sec/op    │   sec/op     vs base   │   sec/op     vs base   │
ClientDefault/Standard_HTTP_Client_MIXED-96           33.10m ± 5%
ClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96                  39.84m ± 2%
ClientSSL/Custom_OSSL_Client_MIXED-96                                                    89.99m ± 6%
geomean                                               33.10m        39.84m       ? ¹ ²   89.99m       ? ¹ ²
¹ benchmark set differs from baseline; geomeans may not be comparable
² ratios must be >0 to compute geomean

                                                   │ http-default │     ssl-cached      │     ssl-default      │
                                                   │     B/op     │     B/op      vs base   │     B/op       vs base   │
ClientDefault/Standard_HTTP_Client_MIXED-96          102.3Ki ± 4%
ClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96                  663.1Ki ± 5%
ClientSSL/Custom_OSSL_Client_MIXED-96                                                     792.0Ki ± 10%
geomean                                              102.3Ki        663.1Ki       ? ¹ ²   792.0Ki        ? ¹ ²
¹ benchmark set differs from baseline; geomeans may not be comparable
² ratios must be >0 to compute geomean

                                                   │ http-default │     ssl-cached     │     ssl-default     │
                                                   │  allocs/op   │  allocs/op   vs base   │  allocs/op    vs base   │
ClientDefault/Standard_HTTP_Client_MIXED-96            539.5 ± 7%
ClientCachedSSL/Custom_OSSL_Client_Cached_MIXED-96                  20.22k ± 5%
ClientSSL/Custom_OSSL_Client_MIXED-96                                                    24.58k ± 11%
geomean                                                539.5        20.22k       ? ¹ ²   24.58k        ? ¹ ²
¹ benchmark set differs from baseline; geomeans may not be comparable
² ratios must be >0 to compute geomean
```

Caching the SSL context provides a significant performance benefit in this scenario, cutting the operation time by more than half compared to creating a new context each time. The CGO OpenSSL implementations use significantly more memory, with the cached version being slightly more efficient. The `fipstls` implementation makes many more allocations, though caching helps reduce this somewhat.

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- The [golang-fips](https://github.com/golang-fips/openssl/tree/v2) shim layer of Red Hat's fork of [golang](https://github.com/golang-fips/go).
- The portable OpenSSL implementation is ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Code of Conduct

This project adopts the Go code of conduct: https://go.dev/conduct.
