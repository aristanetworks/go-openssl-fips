#!/usr/bin/env bash

cleanup() {
    echo "Caught cancellation signal. Terminating background processes..."
    pkill -P $$
    exit 1
}

trap cleanup SIGINT SIGTERM

TAG=$(git rev-parse --short HEAD)
DOCKERFILE="./scripts/Dockerfile"

start_time=$(date +%s)
targets=("test-ossl3-alpine" "test-ossl1.1.1-glibc2.31" "test-ossl3-glibc2.36")
pids=()

# Run docker builds in parallel
for target in "${targets[@]}"; do
    (
        docker build --target "$target" --progress=plain -t "$target":"$TAG" -f "$DOCKERFILE" . 2>&1 | sed "s/^/[$target] /"
        exit ${PIPESTATUS[0]}
    ) &
    pids+=($!)
done

# Check builds in background
while [ ${#pids[@]} -gt 0 ]; do
    for pid in "${!pids[@]}"; do
        if ! kill -0 ${pids[$pid]} 2>/dev/null; then
            wait ${pids[$pid]} || {
                pkill -P $$
                exit 1
            }
            unset pids[$pid]
        fi
    done
    sleep 0.1
done

end_time=$(date +%s)
duration=$((end_time - start_time))
printf "Total time: %dm %ds\n" $((duration / 60)) $((duration % 60))
