# Used to test forward compatibility of glibc 2.17
FROM centos:7.9.2009 AS golang-1.23-centos

# install golang
ENV PATH=$PATH:/usr/local/go/bin
RUN <<EOF
set -e

curl -L -o go1.23.2.linux-amd64.tar.gz https://go.dev/dl/go1.23.2.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz
go version
EOF

# install CGO deps
RUN <<EOF
set -e

rpm -ivh --force \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/make-3.82-24.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/gcc-4.8.5-44.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/cpp-4.8.5-44.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/glibc-devel-2.17-317.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/glibc-headers-2.17-317.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/kernel-headers-3.10.0-1160.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/libmpc-1.0.1-3.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/mpfr-3.1.1-4.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/libgomp-4.8.5-44.el7.x86_64.rpm
EOF

FROM golang-1.23-centos AS test-noossl-fallback

COPY . /go/src/go-openssl

# check we can fallback on libdl failures
ENV CGO_ENABLED=1
WORKDIR /go/src/go-openssl
RUN <<EOF
set -e

go test -tags netgo -c -o ssl-client-glibc-2.17 ./fipstls/client_test.go
ldd --version

# should fail
ldd ssl-client-glibc-2.17
export GO_OPENSSL_VERSION_OVERRIDE="4.20"
./ssl-client-glibc-2.17 | grep -q "can't load libssl"
EOF

FROM golang-1.23-centos AS test-ossl1.0.2-glibc2.17

# install openssl 1.0.2k
RUN <<EOF
set -e

rpm -ivh --force \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/openssl-1.0.2k-19.el7.x86_64.rpm \
    https://vault.centos.org/7.9.2009/os/x86_64/Packages/openssl-libs-1.0.2k-19.el7.x86_64.rpm \
EOF

COPY . /go/src/go-openssl

# run unit tests and build test binary
ENV CGO_ENABLED=1
WORKDIR /go/src/go-openssl
RUN <<EOF
set -e

go test -v ./internal/libssl/...
go test -tags netgo -c -o ssl-client-glibc-2.17 ./internal/libssl/...

ldd --version
ldd ssl-client-glibc-2.17
./ssl-client-glibc-2.17
EOF

# test 2.17 binary on glibc 2.31
FROM golang:1.23.2-bullseye AS test-ossl1.1.1-glibc2.31
COPY --from=test-ossl1.0.2-glibc2.17 /go/src/go-openssl /go/src/go-openssl

WORKDIR /go/src/go-openssl
RUN <<EOF
set -e

openssl version
ldd --version
ldd ssl-client-glibc-2.17
./ssl-client-glibc-2.17
EOF

# test 2.17 binary on glibc 2.36
FROM golang:1.23.2-bookworm AS test-ossl3-glibc2.36
COPY --from=test-ossl1.0.2-glibc2.17 /go/src/go-openssl /go/src/go-openssl

WORKDIR /go/src/go-openssl
RUN <<EOF
set -e

openssl version
ldd --version
ldd ssl-client-glibc-2.17
./ssl-client-glibc-2.17
EOF
