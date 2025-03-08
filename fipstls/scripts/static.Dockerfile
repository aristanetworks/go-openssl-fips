FROM golang:1.24.0-alpine AS test-size-diff

RUN apk add --no-cache \
    bash \
    gcc \
    g++ \
    make \
    openssl-dev \
    openssl-libs-static \
    musl-dev \
    linux-headers

ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

COPY . /go/src/fipstls

WORKDIR /go/src/fipstls

RUN bash ./scripts/static-size-diff.sh

FROM debian:buster AS test-glibc2.28

RUN apt-get update && apt-get install ca-certificates -y

COPY --from=test-size-diff /go/src/fipstls/internal/testutils/certs /internal/testutils/certs
COPY --from=test-size-diff /fipstls-client-static /fipstls-client-static

RUN /fipstls-client-static -test.v -noparallel

FROM almalinux:9.5 AS test-glibc2.34

COPY --from=test-glibc2.28 /internal/testutils/certs /internal/testutils/certs
COPY --from=test-glibc2.28 /fipstls-client-static /fipstls-client-static

RUN /fipstls-client-static -test.v -noparallel
