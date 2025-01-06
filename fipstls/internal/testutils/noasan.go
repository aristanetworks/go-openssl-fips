//go:build !asan
// +build !asan

package testutils

import "testing"

// LeakCheck is a no-op when address sanitizer is not enabled.
func LeakCheck(t testing.TB) {}
