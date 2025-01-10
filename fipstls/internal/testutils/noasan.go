//go:build !asan
// +build !asan

package testutils

import "testing"

// LeakCheck is a no-op when address sanitizer is not enabled.
func LeakCheck(t testing.TB) {
	t.Log("Skipping memory leak check... to run this, use '-tags=asan -asan'")
}
