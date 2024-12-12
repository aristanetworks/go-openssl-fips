#!/bin/sh
# These are crude tests to verify glibc 2.17 forward compatibility:

TAG=$(git rev-parse HEAD)
TS=$(date +%s)

case "$1" in
-a|--asan)
    go test -asan -failfast -count=1 ./...
    break
    ;;
-b|--binary)
    go test -tags netgo -race -c -o test-client ./ssl_client_test.go
    go test -tags netgo -race -c -o test-conn ./ssl_conn_test.go

    ./test-conn -test.v -test.count 10
    ./test-client -test.v -test.count 10
    break
    ;;
-t|--trace)
    mkdir -p ./test/trace
    go test -tags netgo -race -c -o test-client ./ssl_client_test.go
    go test -tags netgo -race -c -o test-conn ./ssl_conn_test.go

    ./test-conn -test.v -test.trace ./test/trace/test-conn-trace.out."$TAG.$TS" -test.count 10
    ./test-client -test.v -test.trace ./test/trace/test-client-trace.out."$TAG.$TS" -test.count 10
    break
    ;;
*)
    DOCKERFILE=./scripts/glibc2.17-compat.Dockerfile

    # -- noossl tests --
    # 1) the binary is built with glibc 2.17 without libssl
    # 2) the binary is run without libssl and fallback and dlopen error is confirmed

    docker build \
        --target test-noossl-fallback \
        --progress=plain \
        -t test-noossl-fallback:"$TAG" \
        -f "$DOCKERFILE" .

    # -- ossl tests --
    # 1) the binary is built with glibc 2.17 and tested with openssl 1.0.2k
    # 2) the glibc 2.17 binary is tested with glibc 2.31 & openssl 1.1.1w
    # 3) the glibc 2.17 binary is tested with glibc 2.36 & openssl 3.x

    docker build \
        --target test-ossl1.1.1-glibc2.31 \
        --progress=plain \
        -t test-ossl1.1.1-glibc2.31:"$TAG" \
        -f "$DOCKERFILE" .

    docker build \
        --target test-ossl3-glibc2.36 \
        --progress=plain \
        -t test-ossl3-glibc2.36:"$TAG" \
        -f "$DOCKERFILE" .
    break
    ;;
esac
