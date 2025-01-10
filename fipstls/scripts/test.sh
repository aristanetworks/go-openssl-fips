#!/bin/sh
# run by build.sh
set -ex

export CGO_ENABLED=1
TEST_FLAGS="-v -count=1 -failfast -parallel 4"
DEBUG_FLAGS="-tracegrpc -traceclient -traceserver -tracecgo"
GODEBUG_OPTS="http2debug=2,http2client=2,http2server=2,netdns=debug"
# export GODEBUG=$GODEBUG_OPTS

case "$1" in
-m | -main)
    go test $TEST_FLAGS ./...
    go test $TEST_FLAGS -stresstest -run TestGrpcBidiStress ./...
    go test -v -count=1 -fallbacktest -run TestInitFailure .
    if [ ! -f "/etc/alpine-release" ]; then
        echo "Running tests with address sanitizer..."
        go test $TEST_FLAGS -stresstest -tags=asan -asan ./...
    fi
    break
    ;;
-c | -cover)
    go test $TEST_FLAGS -stresstest -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    break
    ;;
-b | -bench)
    go test -v -run=^$ -bench=BenchmarkGrpcBidiStream -benchmem -count=1 .
    ;;
esac
