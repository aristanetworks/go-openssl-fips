package ossl

import (
	"runtime"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// runWithLockedOSThread ensures the given function executes with the goroutine locked to an OS thread.
func runWithLockedOSThread(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	libssl.SSLClearError()
	return fn()
}
