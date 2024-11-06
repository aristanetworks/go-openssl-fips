# Benchmark Results

## SSL vs Default http.Client testing against httpbingo.org

### GET, POST, & MIXED
```
> go test -bench "BenchmarkClient*" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  51          22866676 ns/op           63743 B/op        149 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 47 Heap Alloc: 1486 KB Heap Sys: 7424 KB
    ssl_bench_test.go:52: CGO Calls: 245 Heap Alloc: 3223 KB Heap Sys: 7360 KB
    ssl_bench_test.go:52: CGO Calls: 551 Heap Alloc: 3708 KB Heap Sys: 7360 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 50          41683497 ns/op           35012 B/op        239 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 553 Heap Alloc: 1325 KB Heap Sys: 7296 KB
    ssl_bench_test.go:68: CGO Calls: 1308 Heap Alloc: 2952 KB Heap Sys: 6848 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                31         197393467 ns/op           50675 B/op        198 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 1577 Heap Alloc: 1600 KB Heap Sys: 11360 KB
    ssl_bench_test.go:99: CGO Calls: 1916 Heap Alloc: 2803 KB Heap Sys: 11200 KB
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            50          23335527 ns/op           56113 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           50          39323585 ns/op          153264 B/op        942 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          36          32734254 ns/op          101489 B/op        517 allocs/op
PASS
ok      github.com/golang-fips/openssl/v2       16.101s
```

### GET
```
> go test -count 10  -bench "BenchmarkClient*/GET" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  51          23357216 ns/op           63813 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 47 Heap Alloc: 1486 KB Heap Sys: 7424 KB
    ssl_bench_test.go:52: CGO Calls: 245 Heap Alloc: 3221 KB Heap Sys: 7360 KB
    ssl_bench_test.go:52: CGO Calls: 551 Heap Alloc: 3709 KB Heap Sys: 7296 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  49          23394209 ns/op           63773 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 557 Heap Alloc: 1285 KB Heap Sys: 7296 KB
    ssl_bench_test.go:52: CGO Calls: 851 Heap Alloc: 3682 KB Heap Sys: 7264 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23268098 ns/op           63682 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 857 Heap Alloc: 1301 KB Heap Sys: 7232 KB
    ssl_bench_test.go:52: CGO Calls: 1157 Heap Alloc: 3691 KB Heap Sys: 7200 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23509400 ns/op           63804 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 1163 Heap Alloc: 1308 KB Heap Sys: 7200 KB
    ssl_bench_test.go:52: CGO Calls: 1463 Heap Alloc: 3699 KB Heap Sys: 7168 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23465184 ns/op           63735 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 1469 Heap Alloc: 1316 KB Heap Sys: 7168 KB
    ssl_bench_test.go:52: CGO Calls: 1769 Heap Alloc: 3687 KB Heap Sys: 7168 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23354575 ns/op           63682 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 1775 Heap Alloc: 1322 KB Heap Sys: 7168 KB
    ssl_bench_test.go:52: CGO Calls: 2075 Heap Alloc: 3668 KB Heap Sys: 7168 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23476003 ns/op           63665 B/op        147 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 2081 Heap Alloc: 1319 KB Heap Sys: 7168 KB
    ssl_bench_test.go:52: CGO Calls: 2381 Heap Alloc: 3718 KB Heap Sys: 7168 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23363717 ns/op           63681 B/op        148 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 2387 Heap Alloc: 1320 KB Heap Sys: 7168 KB
    ssl_bench_test.go:52: CGO Calls: 2687 Heap Alloc: 3720 KB Heap Sys: 7168 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23292027 ns/op           63644 B/op        147 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 2693 Heap Alloc: 1322 KB Heap Sys: 7168 KB
    ssl_bench_test.go:52: CGO Calls: 2993 Heap Alloc: 3705 KB Heap Sys: 7168 KB
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23384873 ns/op           63814 B/op        149 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_GET-96
    ssl_bench_test.go:52: CGO Calls: 2999 Heap Alloc: 1323 KB Heap Sys: 7168 KB
    ssl_bench_test.go:52: CGO Calls: 3299 Heap Alloc: 3697 KB Heap Sys: 7168 KB
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            52          22702697 ns/op           56100 B/op        147 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            50          23029762 ns/op           56132 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            52          23562552 ns/op           56069 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            50          24428141 ns/op           56107 B/op        147 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            52          23088456 ns/op           56066 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            51          23036129 ns/op           56088 B/op        148 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            51          22949276 ns/op           56157 B/op        149 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            51          22844622 ns/op           56062 B/op        147 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            50          23080221 ns/op           56093 B/op        147 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_GET-96            51          23206880 ns/op           56068 B/op        147 allocs/op
PASS
ok      github.com/golang-fips/openssl/v2       25.254s
```

### POST

```
> go test -count 10  -bench "BenchmarkClient*/POST" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 33          42945665 ns/op           37047 B/op        242 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 43 Heap Alloc: 1450 KB Heap Sys: 3392 KB
    ssl_bench_test.go:68: CGO Calls: 543 Heap Alloc: 2380 KB Heap Sys: 7200 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 33          41482070 ns/op           35934 B/op        237 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 723 Heap Alloc: 1435 KB Heap Sys: 7424 KB
    ssl_bench_test.go:68: CGO Calls: 1223 Heap Alloc: 2406 KB Heap Sys: 7136 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 33          44629649 ns/op           36278 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 1403 Heap Alloc: 1494 KB Heap Sys: 7328 KB
    ssl_bench_test.go:68: CGO Calls: 1903 Heap Alloc: 2450 KB Heap Sys: 7040 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 32          47352242 ns/op           32095 B/op        237 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 2083 Heap Alloc: 1507 KB Heap Sys: 7296 KB
    ssl_bench_test.go:68: CGO Calls: 2283 Heap Alloc: 1829 KB Heap Sys: 7200 KB
    ssl_bench_test.go:68: CGO Calls: 2828 Heap Alloc: 2439 KB Heap Sys: 7040 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 32          42558734 ns/op           36493 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 3003 Heap Alloc: 1542 KB Heap Sys: 7264 KB
    ssl_bench_test.go:68: CGO Calls: 3488 Heap Alloc: 2478 KB Heap Sys: 6976 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30          42234415 ns/op           36588 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 3663 Heap Alloc: 1595 KB Heap Sys: 7200 KB
    ssl_bench_test.go:68: CGO Calls: 4118 Heap Alloc: 2440 KB Heap Sys: 6944 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 33          47765854 ns/op           36146 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 4283 Heap Alloc: 1580 KB Heap Sys: 7168 KB
    ssl_bench_test.go:68: CGO Calls: 4783 Heap Alloc: 2560 KB Heap Sys: 6880 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 32          40793049 ns/op           36317 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 4963 Heap Alloc: 1670 KB Heap Sys: 7104 KB
    ssl_bench_test.go:68: CGO Calls: 5448 Heap Alloc: 2560 KB Heap Sys: 6848 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 32          42918621 ns/op           35389 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 5623 Heap Alloc: 1641 KB Heap Sys: 7072 KB
    ssl_bench_test.go:68: CGO Calls: 6108 Heap Alloc: 2556 KB Heap Sys: 6816 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30          40666895 ns/op           36670 B/op        238 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:68: CGO Calls: 6283 Heap Alloc: 1728 KB Heap Sys: 7040 KB
    ssl_bench_test.go:68: CGO Calls: 6738 Heap Alloc: 2563 KB Heap Sys: 6784 KB
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           27          41083982 ns/op          148005 B/op        933 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           31          39603123 ns/op          145801 B/op        937 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           32          40205361 ns/op          150982 B/op        938 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           30          39795003 ns/op          150368 B/op        930 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           32          42357710 ns/op          153081 B/op        938 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           30          40897878 ns/op          148562 B/op        931 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           33          39611387 ns/op          147577 B/op        935 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           32          42715458 ns/op          147221 B/op        937 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           31          39366401 ns/op          148416 B/op        936 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_POST-96           31          39488697 ns/op          145784 B/op        929 allocs/op
PASS
ok      github.com/golang-fips/openssl/v2       29.026s
```

### MIXED
```
> go test -count 10  -bench "BenchmarkClient*/MIXED" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                32          32308261 ns/op           50111 B/op        197 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 47 Heap Alloc: 1481 KB Heap Sys: 7488 KB
    ssl_bench_test.go:99: CGO Calls: 388 Heap Alloc: 2726 KB Heap Sys: 7264 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                33          34492990 ns/op           42944 B/op        208 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 497 Heap Alloc: 1461 KB Heap Sys: 7392 KB
    ssl_bench_test.go:99: CGO Calls: 691 Heap Alloc: 1865 KB Heap Sys: 7200 KB
    ssl_bench_test.go:99: CGO Calls: 1152 Heap Alloc: 2817 KB Heap Sys: 7072 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                31          33739504 ns/op           49667 B/op        200 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 1277 Heap Alloc: 1498 KB Heap Sys: 7232 KB
    ssl_bench_test.go:99: CGO Calls: 1630 Heap Alloc: 2800 KB Heap Sys: 7072 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                44          34419777 ns/op           49882 B/op        196 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 1739 Heap Alloc: 1525 KB Heap Sys: 7200 KB
    ssl_bench_test.go:99: CGO Calls: 1990 Heap Alloc: 3048 KB Heap Sys: 7168 KB
    ssl_bench_test.go:99: CGO Calls: 2510 Heap Alloc: 2732 KB Heap Sys: 7008 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                32          32788815 ns/op           50240 B/op        199 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 2645 Heap Alloc: 1507 KB Heap Sys: 7200 KB
    ssl_bench_test.go:99: CGO Calls: 3004 Heap Alloc: 2886 KB Heap Sys: 7072 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                39          29263069 ns/op           52404 B/op        174 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 3109 Heap Alloc: 1523 KB Heap Sys: 7232 KB
    ssl_bench_test.go:99: CGO Calls: 3376 Heap Alloc: 2922 KB Heap Sys: 7136 KB
    ssl_bench_test.go:99: CGO Calls: 3768 Heap Alloc: 2843 KB Heap Sys: 7040 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                37          31086728 ns/op           46348 B/op        195 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 3857 Heap Alloc: 1522 KB Heap Sys: 7072 KB
    ssl_bench_test.go:99: CGO Calls: 4174 Heap Alloc: 2856 KB Heap Sys: 6976 KB
    ssl_bench_test.go:99: CGO Calls: 4656 Heap Alloc: 3193 KB Heap Sys: 6880 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                28          36449354 ns/op           55803 B/op        191 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 4771 Heap Alloc: 1616 KB Heap Sys: 7008 KB
    ssl_bench_test.go:99: CGO Calls: 5065 Heap Alloc: 2910 KB Heap Sys: 6880 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                50          34464863 ns/op           50216 B/op        201 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 5131 Heap Alloc: 1605 KB Heap Sys: 6944 KB
    ssl_bench_test.go:99: CGO Calls: 5697 Heap Alloc: 3169 KB Heap Sys: 6720 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                31          34762010 ns/op           48776 B/op        203 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:99: CGO Calls: 5867 Heap Alloc: 1669 KB Heap Sys: 6976 KB
    ssl_bench_test.go:99: CGO Calls: 6229 Heap Alloc: 2889 KB Heap Sys: 6848 KB
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          40          33552587 ns/op          113981 B/op        619 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          31          32515991 ns/op          108029 B/op        577 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          37          31768587 ns/op          105386 B/op        552 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          30          34489965 ns/op          104267 B/op        541 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          51          33637193 ns/op          102789 B/op        538 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          37          32870607 ns/op          106620 B/op        551 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          50          29934864 ns/op           93656 B/op        445 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          50          31364464 ns/op          102252 B/op        523 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          37          31581351 ns/op          107136 B/op        553 allocs/op
BenchmarkClientDefault/Standard_HTTP_Client_MIXED-96          49          33911178 ns/op          108719 B/op        566 allocs/op
PASS
ok      github.com/golang-fips/openssl/v2       32.769s
```

## SSL http.Client only testing against httpbingo.org
### GET
```
> go test -count 10 -bench "BenchmarkClientSSL*/GET" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23204872 ns/op           63839 B/op        148 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23525905 ns/op           63765 B/op        149 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23067619 ns/op           63781 B/op        148 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23324182 ns/op           63798 B/op        148 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  51          23020441 ns/op           63762 B/op        148 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23055528 ns/op           63744 B/op        147 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  51          23527381 ns/op           63617 B/op        147 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23148884 ns/op           63659 B/op        147 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  51          23194594 ns/op           63599 B/op        147 allocs/op
BenchmarkClientSSL/Custom_OSSL_Client_GET-96                  50          23378434 ns/op           63668 B/op        147 allocs/op
PASS
ok      github.com/golang-fips/openssl/v2       12.440s
```

### POST
```
> go test -count 10 -bench "BenchmarkClientSSL*/POST" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 33          44110330 ns/op           37448 B/op        245 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 43 Heap Alloc: 1466 KB Heap Sys: 3296 KB
    ssl_bench_test.go:66: CGO Calls: 543 Heap Alloc: 2409 KB Heap Sys: 7104 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 34          45713083 ns/op           36388 B/op        240 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 723 Heap Alloc: 1453 KB Heap Sys: 7328 KB
    ssl_bench_test.go:66: CGO Calls: 1238 Heap Alloc: 2467 KB Heap Sys: 7072 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30         206551598 ns/op           37025 B/op        241 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 1423 Heap Alloc: 1478 KB Heap Sys: 7296 KB
    ssl_bench_test.go:66: CGO Calls: 1878 Heap Alloc: 2387 KB Heap Sys: 7008 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30          39337453 ns/op           36817 B/op        239 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 2043 Heap Alloc: 1552 KB Heap Sys: 7200 KB
    ssl_bench_test.go:66: CGO Calls: 2498 Heap Alloc: 2414 KB Heap Sys: 6944 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 28          39571682 ns/op           35659 B/op        237 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 2663 Heap Alloc: 1589 KB Heap Sys: 7136 KB
    ssl_bench_test.go:66: CGO Calls: 3088 Heap Alloc: 2334 KB Heap Sys: 6912 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 31         203552266 ns/op           36716 B/op        240 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 3243 Heap Alloc: 1571 KB Heap Sys: 7104 KB
    ssl_bench_test.go:66: CGO Calls: 3713 Heap Alloc: 2480 KB Heap Sys: 6848 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30          40188829 ns/op           36833 B/op        239 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 3883 Heap Alloc: 1620 KB Heap Sys: 7072 KB
    ssl_bench_test.go:66: CGO Calls: 4338 Heap Alloc: 2468 KB Heap Sys: 6848 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 33          40347310 ns/op           36418 B/op        240 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 4503 Heap Alloc: 1601 KB Heap Sys: 7072 KB
    ssl_bench_test.go:66: CGO Calls: 5003 Heap Alloc: 2579 KB Heap Sys: 6816 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 32          42709523 ns/op           36740 B/op        241 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 5183 Heap Alloc: 1612 KB Heap Sys: 7040 KB
    ssl_bench_test.go:66: CGO Calls: 5668 Heap Alloc: 2580 KB Heap Sys: 6784 KB
BenchmarkClientSSL/Custom_OSSL_Client_POST-96                 30          40371203 ns/op           36741 B/op        239 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_POST-96
    ssl_bench_test.go:66: CGO Calls: 5843 Heap Alloc: 1675 KB Heap Sys: 7040 KB
    ssl_bench_test.go:66: CGO Calls: 6298 Heap Alloc: 2538 KB Heap Sys: 6784 KB
PASS
ok      github.com/golang-fips/openssl/v2       23.391s
```

### MIXED
```
> go test -count 10 -bench "BenchmarkClientSSL*/MIXED" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                34          33892984 ns/op           51072 B/op        203 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 43 Heap Alloc: 1461 KB Heap Sys: 3328 KB
    ssl_bench_test.go:97: CGO Calls: 423 Heap Alloc: 2888 KB Heap Sys: 7200 KB
PASS
ok      github.com/golang-fips/openssl/v2       1.239s
~/github/aristanetworks/go-openssl-fips @bdhill-home-hn22n> go test -count 10 -bench "BenchmarkClientSSL*/MIXED" -benchmem -run ^$
goos: linux
goarch: amd64
pkg: github.com/golang-fips/openssl/v2
cpu: Intel(R) Xeon(R) Gold 5318Y CPU @ 2.10GHz
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                33          36326017 ns/op           52530 B/op        198 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 43 Heap Alloc: 1462 KB Heap Sys: 3328 KB
    ssl_bench_test.go:97: CGO Calls: 399 Heap Alloc: 2893 KB Heap Sys: 7264 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                38          31742822 ns/op           53715 B/op        186 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 503 Heap Alloc: 1459 KB Heap Sys: 7392 KB
    ssl_bench_test.go:97: CGO Calls: 799 Heap Alloc: 2916 KB Heap Sys: 7200 KB
    ssl_bench_test.go:97: CGO Calls: 1231 Heap Alloc: 2718 KB Heap Sys: 11136 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                51          29673515 ns/op           56109 B/op        181 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 1307 Heap Alloc: 1371 KB Heap Sys: 11200 KB
    ssl_bench_test.go:97: CGO Calls: 1780 Heap Alloc: 3567 KB Heap Sys: 11040 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                31          37777581 ns/op           48550 B/op        203 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 1895 Heap Alloc: 1559 KB Heap Sys: 11168 KB
    ssl_bench_test.go:97: CGO Calls: 2257 Heap Alloc: 2805 KB Heap Sys: 11040 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                33          31869567 ns/op           52673 B/op        185 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 2371 Heap Alloc: 1557 KB Heap Sys: 11168 KB
    ssl_bench_test.go:97: CGO Calls: 2691 Heap Alloc: 2991 KB Heap Sys: 11072 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                31          33774177 ns/op           47933 B/op        202 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 2781 Heap Alloc: 1543 KB Heap Sys: 11136 KB
    ssl_bench_test.go:97: CGO Calls: 3134 Heap Alloc: 2800 KB Heap Sys: 11008 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                36          33892501 ns/op           46909 B/op        197 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 3239 Heap Alloc: 1522 KB Heap Sys: 11168 KB
    ssl_bench_test.go:97: CGO Calls: 3527 Heap Alloc: 2847 KB Heap Sys: 11040 KB
    ssl_bench_test.go:97: CGO Calls: 3983 Heap Alloc: 3188 KB Heap Sys: 10944 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                50          33913078 ns/op           54968 B/op        196 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 4085 Heap Alloc: 1621 KB Heap Sys: 11072 KB
    ssl_bench_test.go:97: CGO Calls: 4619 Heap Alloc: 3430 KB Heap Sys: 10848 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                52          32120583 ns/op           52691 B/op        197 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 4741 Heap Alloc: 1591 KB Heap Sys: 11008 KB
    ssl_bench_test.go:97: CGO Calls: 5305 Heap Alloc: 3368 KB Heap Sys: 10816 KB
BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96                52          31195154 ns/op           54702 B/op        185 allocs/op
--- BENCH: BenchmarkClientSSL/Custom_OSSL_Client_MIXED-96
    ssl_bench_test.go:97: CGO Calls: 5441 Heap Alloc: 1599 KB Heap Sys: 11040 KB
    ssl_bench_test.go:97: CGO Calls: 5942 Heap Alloc: 3552 KB Heap Sys: 10848 KB
PASS
ok      github.com/golang-fips/openssl/v2       15.688s
```