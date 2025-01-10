package fipstls_test

import (
	"flag"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

var (
	useNetDial         = flag.Bool("netdial", false, "Use default net.Dialer")
	runStressTest      = flag.Bool("stresstest", false, "Run bidistream stress test")
	runFallbackTest    = flag.Bool("fallbacktest", false, "Run init fallback test")
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
	if t != nil {
		t.Parallel()
	}
	if *enableCgoTrace {
		libssl.SetTraceMode(libssl.TraceEnabled)
	}
}
