#!/bin/sh

docker build --progress=plain -t go-openssl-fips:$(git rev-parse HEAD) -f ./scripts/libssl.Dockerfile .
