package fipstls

import (
	"io"
	"runtime"
	"sync"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// runWithLockedOSThread ensures the given function executes with the goroutine
// locked to an OS thread.
func runWithLockedOSThread(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	libssl.SSLClearError()
	return fn()
}

// Closer is [io.Closer] that will return the closer error.
type Closer interface {
	// Err returns the error from the Close function.
	Err() error
	io.Closer
}

// noopCloser is the default closer that does nothing.
type noopCloser struct{}

func (noopCloser) Err() error   { return nil }
func (noopCloser) Close() error { return nil }

// onceCloser will call closeFunc once and store the return error.
type onceCloser struct {
	closeOnce sync.Once
	closeFunc func() error
	closeErr  error
}

func (o *onceCloser) Err() error {
	return o.closeErr
}
func (o *onceCloser) Close() error {
	o.closeOnce.Do(func() {
		o.closeErr = o.closeFunc()
	})
	return o.closeErr
}