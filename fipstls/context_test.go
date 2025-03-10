package fipstls_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

func TestInitFailure(t *testing.T) {
	if !*runFallbackTest {
		t.Skip("Skipping... to run this, use '-fallbacktest'")
	}
	tests := []struct {
		name        string
		expErr      bool
		version     string
		versionText string
		libsslInit  bool
	}{
		{
			name:    "init non-existing version",
			expErr:  true,
			version: "libssl.so.1.2.3",
		},
		{
			name:        "init existing version",
			expErr:      false,
			version:     "libssl.so.3",
			versionText: "OpenSSL 3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			libssl.Reset()
			err := fipstls.Init(tc.version)
			if tc.expErr && !errors.Is(err, fipstls.ErrLoadLibSslFailed) {
				t.Fatalf("Expected err %v, got err %v", fipstls.ErrLoadLibSslFailed, err)
			}
			if !tc.expErr {
				got := fipstls.Version()
				if !strings.Contains(got, tc.versionText) {
					t.Fatalf("Expected versionText %v, got versionText %v", tc.version, got)
				}
			}
		})
	}
}

func TestFIPSMode(t *testing.T) {
	if !*runFallbackTest {
		t.Skip("Skipping... to run this, use '-fallbacktest'")
	}
	if !fipstls.FIPSMode() {
		if err := fipstls.SetFIPS(true); err != nil {
			t.Fatalf("SetFIPS() returned unexpected error %v", err)
		}
		if !fipstls.FIPSMode() {
			t.Fatal("FIPSMode() expected to return true, got false")
		}
	}
}
