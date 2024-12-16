package testutils

import (
	"runtime"
	"time"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

type testLogger interface {
	Logf(format string, args ...any)
}

// LeadCheckLSAN will check for memory leaks if tests are run with 'go test -asan' address sanitizer.
// This should be run at the very end of the Test.
func LeakCheckLSAN(t testLogger) {
	t.Logf("checking for memory leaks if address sanitizer enabled w/ 'go test -asan ...'")
	for range 5 {
		// Run GC a few times to avoid false positives in leak detection.
		runtime.GC()
		// Sleep a bit to let the finalizers run.
		time.Sleep(100 * time.Millisecond)
	}
	libssl.CheckLeaks()
}
