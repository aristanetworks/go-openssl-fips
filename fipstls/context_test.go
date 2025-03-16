package fipstls_test

import (
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

func TestNewCtx(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)

	testCases := []struct {
		name    string
		config  *fipstls.Config
		wantErr bool
	}{
		{
			name:    "Default config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "Custom config",
			config: &fipstls.Config{
				MinTLSVersion: fipstls.Version12,
				MaxTLSVersion: fipstls.Version13,
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := fipstls.NewCtx(tc.config)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewCtx() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && ctx == nil {
				t.Fatal("Expected non-nil Context when no error")
			}
			if ctx != nil {
				// Test that we can access the underlying context
				sslCtx := ctx.Ctx()
				if sslCtx == nil {
					t.Error("Ctx() returned nil")
				}

				// Test Close method
				if err := ctx.Close(); err != nil {
					t.Fatalf("Context.Close() failed: %v", err)
				}

				// Calling Close again should be safe (onceCloser)
				if err := ctx.Close(); err != nil {
					t.Fatalf("Context.Close() failed on second call: %v", err)
				}
			}
		})
	}
}

func TestContextWithConfig(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)

	testCases := []struct {
		name   string
		config *fipstls.Config
	}{
		{
			name: "With TLS versions",
			config: &fipstls.Config{
				MinTLSVersion: fipstls.Version12,
				MaxTLSVersion: fipstls.Version13,
			},
		},
		{
			name: "With CaFile",
			config: &fipstls.Config{
				CaFile: testutils.CertPath,
			},
		},
		{
			name: "With HTTP/2",
			config: &fipstls.Config{
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		{
			name: "With security options",
			config: &fipstls.Config{
				SessionTicketsDisabled: true,
				RenegotiationDisabled:  true,
				CompressionDisabled:    true,
			},
		},
		{
			name: "With verify modes",
			config: &fipstls.Config{
				VerifyMode: fipstls.VerifyFailIfNoPeerCert,
			},
		},
		{
			name: "With insecure skip verify",
			config: &fipstls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := fipstls.NewCtx(tc.config)
			if err != nil {
				t.Fatalf("NewCtx() error = %v", err)
			}
			defer ctx.Close()

			if ctx.Ctx() == nil {
				t.Error("Ctx() returned nil")
			}
		})
	}
}
