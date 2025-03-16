//go:build !cgo

package libssl_test

import (
	"errors"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

func TestCgoDisabled(t *testing.T) {
	err := libssl.Init("")
	if err == nil {
		t.Logf("Init() err = nil, expected: %v", libssl.ErrMethodUnimplemented)
	} else if !errors.Is(err, libssl.ErrMethodUnimplemented) {
		t.Logf("Init() err = %v, expected: %v", err, libssl.ErrMethodUnimplemented)
	}
	if libssl.FIPS() {
		t.Error("FIPSMode() = true, expected false")
	}
	err = libssl.SetFIPS(true)
	if err == nil {
		t.Logf("SetFIPS(true) err = nil, expected: %v", libssl.ErrMethodUnimplemented)
	} else if !errors.Is(err, libssl.ErrMethodUnimplemented) {
		t.Logf("SetFIPS(true) err = %v, expected: %v", err, libssl.ErrMethodUnimplemented)
	}
}
