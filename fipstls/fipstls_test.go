package fipstls_test

import (
	"flag"
	"testing"
)

var (
	useNetDial         = flag.Bool("netdial", false, "Use default net.Dialer")
	runStressTest      = flag.Bool("stress", false, "Run bidistream stress test")
	enableClientTrace  = flag.Bool("traceclient", false, "Enable client connection tracing")
	enableServerTrace  = flag.Bool("traceserver", false, "Enable server connection tracing")
	enableProgRecorder = flag.Bool("showprog", false, "Enable progress recorder output")
)

func TestMain(m *testing.M) {
	testing.Init()
	m.Run()
}
