package fipstls_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

func TestInitFailure(t *testing.T) {
	if !*runInitTest {
		t.Skip("Skipping... to run this, use '-inittest'")
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
			err := fipstls.Init(tc.version)
			defer libssl.Reset()
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

func TestInitFIPSMode(t *testing.T) {
	if !*runInitTest {
		t.Skip("Skipping... to run this, use '-inittest'")
	}
	initTest(t)
	defer libssl.Reset()
	if !fipstls.FIPSMode() {
		if err := fipstls.SetFIPS(true); err != nil {
			if !libssl.FIPSCapable() {
				t.Skip("Skipping... no FIPS-capable provider found")
			}
			t.Fatalf("SetFIPS() returned unexpected error %v", err)
		}
		if !fipstls.FIPSMode() {
			t.Fatal("FIPSMode() expected to return true, got false")
		}
	} else {
		t.Log("FIPS mode is already enabled")
	}
}
