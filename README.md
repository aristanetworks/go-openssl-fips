# Go OpenSSL FIPS TLS Client

[![Go Reference](https://pkg.go.dev/badge/github.com/aristanetworks/go-openssl-fips/fipstls.svg)](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls)

The `fipstls` package implements TLS client methods using OpenSSL shared libraries and cgo. When configured correctly, OpenSSL can be executed in FIPS mode, making the `fipstls` package FIPS compliant.

The `fipstls` package is designed to be used as a drop-in for:
- [http.Client](https://pkg.go.dev/net/http#Client) with TLS enabled
- Dialing [grpc.ClientConn](https://pkg.go.dev/google.golang.org/grpc#ClientConn) with [grpc.WithContextDialer](https://pkg.go.dev/google.golang.org/grpc#WithContextDialer)

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

The [`fipstls.Init`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Init) method dynamically loads the `libssl.so` library. If the `fipstls` package cannot dynamically load the `libssl.so` library, it will gracefully exit with:
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

## Usage

Prior to using any `fipstls` methods, the [`fipstls.Init`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Init) method must be called to dynamically load libssl. If that fails, then the program has the option to handle the error and fallback to default go/crypto.

There are three structs that the caller may use in creating TLS connections:
- The [`fipstls.Config`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Config) struct is used for configuring TLS options for the [`fipstls.Context`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Context).
- The [`fipstls.Dialer`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Dialer) creates a [`fipstls.Context`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Context) for every new [`fipstls.Conn`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Conn) connection. The [`fipstls.Conn`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Conn) connection is responsible for freeing the C memory allocated by OpenSSL when it is closed.
- The [`fipstls.Transport`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Transport) calls into the [`fipstls.Dialer`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#Dialer) for creating a new TLS connection every roundtrip.

**Note**: Creating the context once and reusing it is considered best practice by OpenSSL developers, as internally to OpenSSL various items are shared between multiple SSL objects are cached in the C.SSL_CTX. The drawback is that the caller will be responsible for closing the context which will cleanup the C memory allocated for it. For simplicity and increased memory safety, the context lifecycle will be 1:1 with the connection lifecycle.

### 1. Creating a http.Client

This example demonstrates how to create a default `http.Client` with TLS configured using [`fipstls.NewClient`](https://pkg.go.dev/github.com/aristanetworks/go-openssl-fips/fipstls#NewClient).

```go
import (
	"fmt"
	"net/http"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
)

func main() {
	// Check that we can load libssl.so
	if err := fipstls.Init(""); err != nil {
		// Handle failure and fallback
		log.Fatalf("Failed to initialize fipstls: %v", err)
	}

	// Example 1: Create a default client with TLS configured for TLS 1.3
	client := fipstls.NewClient(&fipstls.Config{
		CaFile: "/path/to/cert.pem",
		MinTLSVersion: fipstls.Version13,
	})
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatalf("Failed get request: %v", err)
	}
	defer resp.Body.Close()

	// Example 2: Create a client with a fipstls.Transport that will modify the request header
	client = &http.Client{
		Transport: &fipstls.Transport{
			Dialer: fipstls.NewDialer(&fipstls.Config{CaFile: "/path/to/cert.pem"}),
			ModifyHeader: func(h *http.Header) {
				h.Add("User-Agent", "foo")
			},
		}
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatalf("Failed get request: %v", err)
	}
	defer resp.Body.Close()

	// Example 3: Create a http.Client with a default fipstls.Transport
	client = &http.Client{Transport: &fipstls.Transport{}}
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatalf("Failed get request: %v", err)
	}
	defer resp.Body.Close()
}
```

### 2. Creating a Dial Function

This example demonstrates how to create a dial function that can be used for dialing [grpc.ClientConn](https://pkg.go.dev/google.golang.org/grpc#ClientConn) with [grpc.WithContextDialer](https://pkg.go.dev/google.golang.org/grpc#WithContextDialer).

``` go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Check that we can load libssl.so
	if err := fipstls.Init(""); err != nil {
		// Handle failure and fallback
		log.Fatalf("Failed to initialize fipstls: %v", err)
	}

	// Create an fipstls.Dialer with the configured context
	dialFn, err := fipstls.NewGrpcDialFn(&fipstls.Config{"/path/to/cert.pem"})
	if err != nil {
		log.Fatalf("Failed to create grpc dialer: %v", err)
	}

	// Use grpc.WithContextDialer to create a gRPC connection that will create
	// a new Context every dial
	conn, err := grpc.NewClient(
		"your-grpc-server-address:port",
		grpc.WithContextDialer(dialFn),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
	   log.Fatalf("creating gRPC new client failed: %v", err)
	}
	// this will free the C memory allocated for the context
	defer conn.Close()

	// ... use the gRPC connection ...
}
```

## Testing

The unit tests are run with `-asan` to test for memory leaks in order to ensure memory safety, and valgrind to analyze total heap usage. The openssl version used in these tests is openssl 3.0.7.

### HTTP Client Benchmarks

In this benchmark, we make a mix of get and post requests to `httpgobin.org`, with the number of iterations measuring the total number of roundtrips completed.

<details>
  <summary>Output</summary>

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
</details>


| Metric | http-default | ssl-cached | ssl-default | geomean |
|---------|--------------|------------|-------------|----------|
| sec/op | **33.10m ± 5%** | 39.84m ± 2% | 89.99m ± 6% | 33.10m/39.84m/89.99m |
| B/op | 102.3Ki ± 4% | 663.1Ki ± 5% | **792.0Ki ± 10%** | 102.3Ki/663.1Ki/792.0Ki |
| allocs/op | **539.5 ± 7%** | 20.22k ± 5% | 24.58k ± 11% | 539.5/20.22k/24.58k |

The default http.Client was able to complete ~50 roundtrips, compared to ~32 in the cached context case, and ~14 in the ephemeral context case (context created every round trip).

In general, using openssl produces higher throughput, which explains 4 to 5x more memory allocations.

In the cached scenario, it is 17% slower per round trip, but has 6x higher throughput.

On the other hand, the default client creates and destroys the context every round trip which over 2x the latency per operation.

In this case, there is a connection being created each request, so the results are consistent with the cost of not-caching the context, and also the costs of re-creating the SSL object every roundtrip. There is no connection caching implemented, so in scenarios with a large number of roundtrips, there will be a noticeable difference in latency.

### Grpc HTTP2 Client Benchmarks

In this benchmark, there are 100 streams with 100,000 messages to be streamed bi-directionally. We compare the `fipstls.Dialer` to the default grpc `net.Dialer`.

<details>
  <summary>Output</summary>

```
goos: linux
goarch: amd64
pkg: github.com/aristanetworks/go-openssl-fips/fipstls
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
                  │ default-grpc │           ssl-grpc            │
                  │    sec/op    │   sec/op     vs base          │
GrpcBidiStream-96    545.5m ± 9%   564.3m ± 6%  ~ (p=0.481 n=10)

                  │ default-grpc │              ssl-grpc               │
                  │    B/msg     │    B/msg      vs base               │
GrpcBidiStream-96   1.403Ki ± 0%   1.449Ki ± 1%  +3.24% (p=0.000 n=10)

                  │ default-grpc │              ssl-grpc               │
                  │     B/op     │     B/op      vs base               │
GrpcBidiStream-96   137.0Mi ± 0%   141.1Mi ± 0%  +3.01% (p=0.000 n=10)

                  │ default-grpc │              ssl-grpc              │
                  │  allocs/op   │  allocs/op   vs base               │
GrpcBidiStream-96    3.900M ± 0%   3.906M ± 0%  +0.15% (p=0.002 n=10)
```
</details>


| Metric | default-grpc | ssl-grpc | Comparison |
|---------|--------------|-----------|------------|
| sec/op | 545.5m ± 9% | 564.3m ± 6% | ~ (p=0.481 n=10) |
| B/msg | 1.403Ki ± 0% | **1.449Ki ± 1%%** | +3.24% (p=0.000 n=10) |
| B/op | 137.0Mi ± 0% | **141.1Mi ± 0%** | +3.01% (p=0.000 n=10) |
| allocs/op | 3.900M ± 0% | 3.906M ± 0% | +0.15% (p=0.002 n=10) |


 Instead of pooling connections like `http.Client.Transport`, grpc is creating a single long-lived connection and multiplexing HTTP/2 streams over it. In this case, there are many concurrent accesses to `fipstls.Conn`, and we only have the incur the context and ssl connection creation cost once in the beginning.

 The openssl implementation manages to push about 3% more bytes in a bidirectional stream, and 3% more messages, with around the same number of memory allocations and latency. The 3% increase in bytes/messages without significant allocation changes suggests that the OpenSSL implementation might be slightly more efficient at buffer management in long-lived connections.

The p-values indicate high statistical significance for the byte metrics (p=0.000) but not for the timing (p=0.481), which supports the conclusion about the throughput improvement.

## Total Heap Usage

| Memory Type | netdial | openssl | Difference |
|------------|----------|----------|------------|
| Go Heap | 1735.87MB | 1861.30MB | +125.43MB (+7.2%) |
| C Heap (peak) | 0.5MB | 1.355MB | +0.855MB (+171%) |
| **Total Heap** | 1736.37MB | 1862.66MB | +126.29MB (+7.3%) |

- Go heap allocation patterns are similar between versions (based on top10)
- OpenSSL shows higher memory usage in both heap types
- C heap shows more complex allocation patterns in OpenSSL version

### OpenSSL Heap Usage

Running:
```
go test -c client_test.go -o benchtest
valgrind --tool=massif ./benchtest -test.bench=BenchmarkGrpcBidiStream
ms_print massif.out.<pid>
```

<details>
	<summary>Massif Output</summary>

```
--------------------------------------------------------------------------------
Command:            ./benchtest -test.bench=BenchmarkGrpcBidiStream
Massif arguments:   (none)
ms_print arguments: massif.out.1100026
--------------------------------------------------------------------------------


    MB
1.355^                                                           #
     |                                                           #:::::::::::
     |                                                           #:
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                           #@
     |                                                    :      #@
     |:::::::::::::::::::::::                             :::::::#@
     |:                      ::::::::::::::::::::::::::::::      #@          @
     |:                      :                            :      #@          @
     |:                      :                            :      #@          @
     |:                      :                            :      #@          @
     |:                      :                            :      #@          @
   0 +----------------------------------------------------------------------->Gi
     0                                                                   37.96

Number of snapshots: 70
 Detailed snapshots: [11, 16, 17, 18, 22, 23 (peak), 39, 49, 59, 69]

--------------------------------------------------------------------------------
  n        time(i)         total(B)   useful-heap(B) extra-heap(B)    stacks(B)
--------------------------------------------------------------------------------
  0              0                0                0             0            0
  1     18,899,679          464,568          378,940        85,628            0
  2    132,991,847          462,488          376,948        85,540            0
  3    143,271,545          492,232          401,545        90,687            0
  4    257,364,233          490,088          399,497        90,591            0
  5    262,756,313          469,592          377,867        91,725            0
  6 13,026,084,494          398,592          311,183        87,409            0
  7 29,677,674,631          398,872          311,457        87,415            0
  8 29,681,878,316          499,816          407,821        91,995            0
  9 29,796,007,945          497,672          405,773        91,899            0
 10 29,801,771,004          476,176          383,199        92,977            0
 11 33,430,485,576          405,144          316,501        88,643            0
78.12% (316,501B) (heap allocation functions) malloc/new/new[], --alloc-fns, etc.

```
</details>

Running:
```
go test -bench=BenchmarkGrpcBidiStream -netdial -benchmem -memprofile=netdial.mem.prof
go tool pprof -alloc_space netdial.mem.prof
```

<details>
	<summary>pprof top10 Output</summary>

```
> go tool pprof -alloc_space netdial.mem.prof
File: fipstls.test
Build ID: f7d6d04a4dc91f30ba06f7eb32b4916886835939
Type: alloc_space
Time: Dec 25, 2024 at 8:29pm (UTC)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top10
Showing nodes accounting for 1013.05MB, 58.36% of 1735.87MB total
Dropped 161 nodes (cum <= 8.68MB)
Showing top 10 nodes out of 81
      flat  flat%   sum%        cum   cum%
  122.51MB  7.06%  7.06%   752.54MB 43.35%  github.com/aristanetworks/go-openssl-fips/fipstls_test.(*testServer).BidiStream
  122.51MB  7.06% 14.11%   122.51MB  7.06%  google.golang.org/grpc/mem.BufferSlice.Reader
     113MB  6.51% 20.62%      113MB  6.51%  google.golang.org/grpc/internal/transport.(*itemList).enqueue (inline)
  111.01MB  6.40% 27.02%   379.22MB 21.85%  google.golang.org/grpc.(*clientStream).SendMsg
  102.01MB  5.88% 32.90%   170.01MB  9.79%  google.golang.org/grpc.(*serverStream).RecvMsg
   97.51MB  5.62% 38.51%    97.51MB  5.62%  google.golang.org/grpc.outPayload (inline)
   93.50MB  5.39% 43.90%   185.01MB 10.66%  google.golang.org/grpc/internal/transport.(*http2Server).write
   92.50MB  5.33% 49.23%      166MB  9.56%  google.golang.org/grpc/encoding/proto.(*codecV2).Marshal
   85.01MB  4.90% 54.13%   255.01MB 14.69%  google.golang.org/grpc.(*GenericServerStream[go.shape.struct { github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto.state google.golang.org/protobuf/internal/impl.MessageState; github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto.sizeCache int32; github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto.unknownFields []uint8; Message string "protobuf:\"bytes,1,opt,name=message,proto3\" json:\"message,omitempty\"" },go.shape.struct { github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto.state google.golang.org/protobuf/internal/impl.MessageState; github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto.sizeCache int32; github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto.unknownFields []uint8; Message string "protobuf:\"bytes,1,opt,name=message,proto3\" json:\"message,omitempty\"" }]).Recv
   73.50MB  4.23% 58.36%    73.50MB  4.23%  google.golang.org/protobuf/proto.MarshalOptions.marshal
(pprof)
```
</details>

## Acknowledgements

The work done to support FIPS compatibility mode leverages code and ideas from other open-source projects:

- The [golang-fips](https://github.com/golang-fips/openssl/tree/v2) shim layer of Red Hat's fork of [golang](https://github.com/golang-fips/go).
- The portable OpenSSL implementation is ported from Microsoft's [.NET runtime](https://github.com/dotnet/runtime) cryptography module.

## Code of Conduct

This project adopts the Go code of conduct: https://go.dev/conduct.
