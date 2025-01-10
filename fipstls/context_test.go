package fipstls_test

import (
	"errors"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

func TestInitFailure(t *testing.T) {
	if !*runFallbackTest {
		t.Skip("Skipping... to run this, use '-fallbacktest'")
	}
	tests := []struct {
		name       string
		expErr     bool
		version    string
		libsslInit bool
	}{
		{
			name:    "init non-existing version",
			expErr:  true,
			version: "libssl.so.1.2.3",
		},
		{
			name:    "init existing version",
			expErr:  false,
			version: "libssl.so.3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			libssl.Reset()
			err := fipstls.Init(tc.version)
			if tc.expErr && !errors.Is(err, fipstls.ErrLoadLibSslFailed) {
				t.Fatal("expected err, got nil")
			}
		})
	}
}
