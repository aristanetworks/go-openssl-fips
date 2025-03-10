package fipstls

import (
	"io"
	"sync"
)

// Closer is [io.Closer] that will return the closer error.
type Closer interface {
	// Err returns the error from the Close function.
	Err() error
	Done() <-chan struct{}
	io.Closer
}

// noopCloser is the default closer that does nothing.
type noopCloser struct{}

func (noopCloser) Err() error            { return nil }
func (noopCloser) Close() error          { return nil }
func (noopCloser) Done() <-chan struct{} { return nil }

// onceCloser will call closeFunc once and store the return error.
type onceCloser struct {
	closeOnce sync.Once
	closeFunc func() error
	closeErr  error
	done      chan struct{}
}

func newOnceCloser(f func() error) Closer {
	return &onceCloser{
		closeFunc: f,
		done:      make(chan struct{}),
	}
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

func (o *onceCloser) Done() <-chan struct{} {
	return o.done
}
