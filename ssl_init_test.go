package ossl_test

import (
	"errors"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/ossl"
)

func TestInitFailure(t *testing.T) {
	t.Skip("need to test in docker env")
	tests := []struct {
		name    string
		expErr  bool
		version string
	}{
		{
			name:    "init non-existing version",
			expErr:  true,
			version: "libssl.so.1.2.3",
		},
		{
			name:    "automatic init after failure",
			expErr:  true,
			version: "",
		},
		{
			name:    "init existing version after failure",
			expErr:  true,
			version: "libssl.so.3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ossl.Init(tc.version)
			if tc.expErr && !errors.Is(err, ossl.ErrLoadLibSslFailed) {
				t.Fatal("expected err, got nil")
			}
		})
	}
}
