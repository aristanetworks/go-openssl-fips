#!/bin/sh

# These are crude tests to verify glibc 2.17 forward compatibility:
# 1) the binary is built with glibc 2.17 and tested with openssl 1.0.2k
# 2) the glibc 2.17 binary is tested with glibc 2.31 & openssl 1.1.1w
# 3) the glibc 2.17 binary is tested with glibc 2.36 & openssl 3.x
docker build --target test-ossl1.1.1-glibc2.31 --progress=plain -t test-ossl1.1.1-glibc2.31:$(git rev-parse HEAD) -f ./scripts/glibc2.17-compat.Dockerfile .
docker build --target test-ossl3-glibc2.36 --progress=plain -t test-ossl3-glibc2.36:$(git rev-parse HEAD) -f ./scripts/glibc2.17-compat.Dockerfile .