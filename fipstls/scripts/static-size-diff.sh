#!/bin/bash
# Script to compare static and dynamic binary sizes

set -e

run_with_echo() {
    set -x
    "$@"
    { set +x; } 2>/dev/null
}

# Build and test binaries
build_and_test() {
    local test_name=$1
    local test_files=$2
    local static_size
    local dynamic_size
    local static_test_passed
    local dynamic_test_passed
    local diff_human
    local percent_increase

    echo "==============================================="
    echo "Testing: $test_name"
    echo "==============================================="

    echo "Building static binary..."
    run_with_echo go test -tags=static -c -o /fipstls-client-static \
        -ldflags '-linkmode external -extldflags "-static"' \
        $test_files

    echo "Verifying static binary..."
    if ldd /fipstls-client-static >/dev/null 2>&1; then
        echo "FAIL (expected no dependencies)"
        static_test_passed="FAIL"
    else
        echo "PASS"
        static_test_passed="PASS"
    fi

    static_bytes=$(du -b /fipstls-client-static | cut -f1)
    static_size=$(echo "scale=2; $static_bytes/1048576" | bc)"M"
    echo "Size: $static_size"

    echo "Building dynamic binary..."
    run_with_echo go test -c -o /fipstls-client \
        $test_files

    echo "Verifying dynamic binary..."
    if ldd /fipstls-client >/dev/null 2>&1; then
        echo "PASS"
        dynamic_test_passed="PASS"
    else
        echo "FAIL (expected dependencies)"
        dynamic_test_passed="FAIL"
    fi

    dynamic_bytes=$(du -b /fipstls-client | cut -f1)
    dynamic_size=$(echo "scale=2; $dynamic_bytes/1048576" | bc)"M"
    echo "Size: $dynamic_size"

    # Calculate difference and percentage
    diff_bytes=$((static_bytes - dynamic_bytes))
    percent_increase=$(awk "BEGIN {printf \"%.1f\", (($static_bytes * 100.0) / $dynamic_bytes) - 100}")

    # Format the difference in human-readable form
    diff_human=$(echo "scale=2; $diff_bytes/1048576" | bc)"M"

    # Store all results including the calculated values
    test_results+=("$test_name|$static_size|$dynamic_size|$diff_human|$percent_increase")
}

declare -a test_results
build_and_test "client_test.go" "client_test.go fipstls_test.go"
build_and_test "all test files" "client_test.go dialer_test.go transport_test.go fipstls_test.go"

echo "==============================================="
echo "                SIZE COMPARISON                "
echo "==============================================="
printf "%-15s | %-10s | %-10s | %-10s | %-10s\n" "Test" "Static" "Dynamic" "Diff" "Increase"
echo "------------------------------------------------------------------------------"

for result in "${test_results[@]}"; do
    IFS='|' read -r test static_size dynamic_size diff_human percent_increase <<<"$result"
    printf "%-15s | %-10s | %-10s | %-10s | %-10s\n" "$test" "$static_size" "$dynamic_size" "$diff_human" "$percent_increase%"
done

echo "==============================================="
