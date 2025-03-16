#!/bin/sh
# test.sh is run in the docker build
set -ex

export CGO_ENABLED=1
# DEBUG_FLAGS="-tracegrpc -traceclient -traceserver -tracecgo"
TEST_FLAGS="-v -count=1 -failfast $DEBUG_FLAGS"
GODEBUG_OPTS="http2debug=2,http2client=2,http2server=2,netdns=debug"
# export GODEBUG=$GODEBUG_OPTS

case "$1" in
-m | -main)
    echo "Running main unit tests..."
    go test $TEST_FLAGS -traceclient ./...
    go test $TEST_FLAGS -stresstest -run TestGrpcBidiStress ./...
    go test -v -count=1 -inittest -run TestInit .
    break
    ;;
-a | -asan)
    if [ ! -f "/etc/alpine-release" ]; then
        echo "Running tests with address sanitizer..."
        go test $TEST_FLAGS -stresstest -tags=asan -asan ./...
    fi
    break
    ;;
-r | -race)
    echo "Running tests with race detector..."
    go test $TEST_FLAGS -stresstest -race ./...
    break
    ;;
-c | -cover)
    echo "Running go test coverage report..."
    go test $TEST_FLAGS -stresstest -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    break
    ;;
-b | -bench)
    echo "Running BenchmarkGrpcBidiStream..."
    go test -v -run=^$ -bench=BenchmarkGrpcBidiStream -benchmem -count=1 .
    break
    ;;
-v | -vet)
    echo "Running go vet..."
    go vet ./...
    break
    ;;
esac
