#!/usr/bin/env bash

# This script runs tests for glibc 2.17 forward compatibility.
# It builds and runs tests in Docker containers with glibc 2.17,
# 2.31 (with openssl 1.1.1w), and 2.36 (with openssl 3.x).
#
# It also builds and runs tests on alpine 3.21 with openssl 3.x.

cleanup() {
    echo "Caught cancellation signal. Terminating background processes..."
    pkill -P $$
    exit 1
}

# Trap SIGINT and SIGTERM signals
trap cleanup SIGINT SIGTERM

TAG=$(git rev-parse --short HEAD)
TS=$(date +%s)
DOCKERFILE="./scripts/Dockerfile"

docker_build() {
    local target=$1
    docker build \
        --target "$target" \
        --progress=plain \
        -t "$target":"$TAG" \
        -f "$DOCKERFILE" .
}

start_time=$(date +%s)
targets=("test-ossl3-alpine" "test-ossl1.1.1-glibc2.31" "test-ossl3-glibc2.36")
pids=()

for target in "${targets[@]}"; do
    docker_build "$target" 2>&1 | sed "s/^/[$target] /" &
    pids+=($!)
done

set -e

for pid in "${pids[@]}"; do
    wait $pid || exit 1
done

end_time=$(date +%s)
duration=$((end_time - start_time))
printf "Total time: %dm %ds\n" $((duration / 60)) $((duration % 60))
