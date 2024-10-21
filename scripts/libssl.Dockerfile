# Used to test the libssl bindings against openssl 3, openssl 1.1.1, and openssl 1.0.2
FROM golang:1.23.2-bullseye AS build-glibc-2.31
COPY . /go/src/go-openssl-fips

# build client binary against glibc-2.31 and test it
WORKDIR /go/src/go-openssl-fips
RUN <<EOF
set -x

openssl version
go test -v ./libssl/...
go test -tags netgo -c -o ssl-client-glibc-2.31 ./libssl/...

ldd --version
ldd ssl-client-glibc-2.31
./ssl-client-glibc-2.31
EOF

FROM golang:1.23.2-bookworm AS build-glibc-2.36
COPY --from=build-glibc-2.31 /go/src/go-openssl-fips /go/src/go-openssl-fips

# build client binary against glibc-2.36 and test it
WORKDIR /go/src/go-openssl-fips
RUN <<EOF
set -x

openssl version
go test -v ./libssl/...
go test -tags netgo -c -o ssl-client-glibc-2.36 ./libssl/...

ldd --version
ldd ssl-client-glibc-2.36
./ssl-client-glibc-2.36
EOF

FROM centos:7.9.2009 AS test-glibc-2.17
COPY --from=build-glibc-2.36 /go/src/go-openssl-fips /go/src/go-openssl-fips

# test client built with 2.31 on glibc 2.17
WORKDIR /go/src/go-openssl-fips
RUN <<EOF
set -x

# openssl version

# linker should fail
ldd ssl-client-glibc-2.36 2>&1 | grep -q 'not found'

# should succeed
ldd --version
ldd ssl-client-glibc-2.31
./ssl-client-glibc-2.31
EOF
