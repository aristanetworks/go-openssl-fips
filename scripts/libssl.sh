#!/bin/sh

# Used to test the libssl bindings against openssl 3, openssl 1.1.1, and openssl 1.0.2
docker build --progress=plain -t go-openssl-fips:$(git rev-parse HEAD) -f ./scripts/libssl.Dockerfile .
