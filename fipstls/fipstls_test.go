package fipstls_test

import (
	"flag"
	"os"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

var (
	useNetDial         = flag.Bool("netdial", false, "Use default net.Dialer")
	runStressTest      = flag.Bool("stresstest", false, "Run bidistream stress test")
	runInitTest        = flag.Bool("inittest", false, "Run init fallback test")
	enableFips         = flag.Bool("fips", false, "Enable FIPS with SetFIPS before running any tests")
	enableClientTrace  = flag.Bool("traceclient", false, "Enable client connection tracing")
	enableServerTrace  = flag.Bool("traceserver", false, "Enable server connection tracing")
	enableProgRecorder = flag.Bool("tracegrpc", false, "Enable progress recorder output")
	enableCgoTrace     = flag.Bool("tracecgo", false, "Enable connection setup tracing in C helper functions")
)

func TestMain(m *testing.M) {
	testing.Init()
	m.Run()
}

func initTest(t *testing.T) {
	if err := fipstls.Init(""); err != nil {
		t.Fatalf("failed to load libssl: %v", err)
	}
	if *enableFips {
		if err := fipstls.SetFIPS(true); err != nil {
			t.Fatalf("SetFIPS(true) err = %v", err)
		}
	}
	if *enableCgoTrace {
		libssl.EnableDebugLogging()
	}
}

func getDialOpts() []fipstls.DialOption {
	o := []fipstls.DialOption{}
	if *enableClientTrace {
		o = append(o, fipstls.WithLogging("", fipstls.LogLevelInfo, os.Stderr))
	}
	return o
}
