package fipstls_test

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"strings"
	"testing"

	"github.com/aristanetworks/glog"
	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

// captureOutput is a helper to capture log output
func captureOutput(f func()) string {
	var buf bytes.Buffer
	original := glog.SetOutput(&buf)
	defer glog.SetOutput(original)
	f()
	return buf.String()
}

// setupGlog ensures glog is initialized for testing
func setupGlog() {
	if !flag.Parsed() {
		// We need to initialize flags for glog
		flag.Parse()
	}
	// Flush any previous logs
	glog.Flush()
}

func TestDefaultLoggerBasic(t *testing.T) {
	var captured []string

	// Create a logger that captures output
	logger := &fipstls.DefaultLogger{
		Prefix: "TEST:",
		Level:  fipstls.LogLevelDebug, // Set to highest level to capture everything
		LoggerFunc: func(format string, args ...any) {
			captured = append(captured, fmt.Sprintf(format, args...))
		},
	}

	// Test different log levels
	logger.Logf(fipstls.LogLevelErr, "Error message")
	logger.Logf(fipstls.LogLevelInfo, "Info message")
	logger.Logf(fipstls.LogLevelDebug, "Debug message")

	if len(captured) != 3 {
		t.Fatalf("Expected 3 log entries, got %d", len(captured))
	}

	// Verify error message format
	if !strings.Contains(captured[0], "ERROR:") || !strings.Contains(captured[0], "TEST:") ||
		!strings.Contains(captured[0], "Error message") {
		t.Errorf("Error message format incorrect: %s", captured[0])
	}

	// Verify info message format
	if !strings.Contains(captured[1], "INFO:") || !strings.Contains(captured[1], "TEST:") ||
		!strings.Contains(captured[1], "Info message") {
		t.Errorf("Info message format incorrect: %s", captured[1])
	}

	// Verify debug message format
	if !strings.Contains(captured[2], "DEBUG:") || !strings.Contains(captured[2], "TEST:") ||
		!strings.Contains(captured[2], "Debug message") {
		t.Errorf("Debug message format incorrect: %s", captured[2])
	}
}

func TestDefaultLoggerLevelFiltering(t *testing.T) {
	var captured []string

	// Create a logger with Info level
	logger := &fipstls.DefaultLogger{
		Prefix: "TEST:",
		Level:  fipstls.LogLevelInfo, // Only ERROR and INFO should be logged
		LoggerFunc: func(format string, args ...any) {
			captured = append(captured, fmt.Sprintf(format, args...))
		},
	}

	// Test all log levels
	logger.Logf(fipstls.LogLevelErr, "Error message")
	logger.Logf(fipstls.LogLevelInfo, "Info message")
	logger.Logf(fipstls.LogLevelDebug, "Debug message") // This should be filtered out

	if len(captured) != 2 {
		t.Fatalf("Expected 2 log entries, got %d", len(captured))
	}

	// Verify error message exists
	if !strings.Contains(captured[0], "ERROR:") {
		t.Errorf("Error message missing: %s", captured[0])
	}

	// Verify info message exists
	if !strings.Contains(captured[1], "INFO:") {
		t.Errorf("Info message missing: %s", captured[1])
	}
}

func TestDefaultLoggerWrap(t *testing.T) {
	var captured []string

	// Create base logger
	logger := &fipstls.DefaultLogger{
		Prefix: "BASE:",
		Level:  fipstls.LogLevelDebug,
		LoggerFunc: func(format string, args ...any) {
			captured = append(captured, fmt.Sprintf(format, args...))
		},
	}

	// Create wrapped logger
	subLogger := logger.Wrap("SUB:")

	// Test that the wrapped logger works
	subLogger.Logf(fipstls.LogLevelInfo, "Wrapped message")

	if len(captured) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(captured))
	}

	// Verify prefix is concatenated
	if !strings.Contains(captured[0], "BASE:SUB:") {
		t.Errorf("Wrapped logger prefix incorrect: %s", captured[0])
	}

	// Create double wrapped logger
	subSubLogger := subLogger.Wrap("SUBSUB:")
	subSubLogger.Logf(fipstls.LogLevelInfo, "Double wrapped message")

	if len(captured) != 2 {
		t.Fatalf("Expected 2 log entries, got %d", len(captured))
	}

	// Verify prefix is concatenated
	if !strings.Contains(captured[1], "BASE:SUB:SUBSUB:") {
		t.Errorf("Double wrapped logger prefix incorrect: %s", captured[1])
	}
}

func TestDefaultLoggerWithFormat(t *testing.T) {
	var captured []string

	logger := &fipstls.DefaultLogger{
		Prefix: "TEST:",
		Level:  fipstls.LogLevelDebug,
		LoggerFunc: func(format string, args ...any) {
			captured = append(captured, fmt.Sprintf(format, args...))
		},
	}

	// Test with formatting
	logger.Logf(fipstls.LogLevelErr, "Error with code %d: %s", 500, "Internal Server Error")

	if len(captured) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(captured))
	}

	// Verify formatting applied correctly
	if !strings.Contains(captured[0], "Error with code 500: Internal Server Error") {
		t.Errorf("Formatted message incorrect: %s", captured[0])
	}
}

func TestWithGlog(t *testing.T) {
	setupGlog()

	// Create a logger that uses glog
	logger := &fipstls.DefaultLogger{
		Prefix:     "GLOG:",
		Level:      fipstls.LogLevelDebug,
		LoggerFunc: glog.Infof,
	}

	// Capture glog output
	output := captureOutput(func() {
		logger.Logf(fipstls.LogLevelErr, "Glog error message")
		logger.Logf(fipstls.LogLevelInfo, "Glog info message")
		glog.Flush() // Make sure logs are flushed
	})
	t.Logf("Captured output: %s", output)

	// Verify glog received our messages
	if !strings.Contains(output, "ERROR:") || !strings.Contains(output, "GLOG:") ||
		!strings.Contains(output, "Glog error message") {
		t.Errorf("Glog error message missing or incorrect: %s", output)
	}

	if !strings.Contains(output, "INFO:") || !strings.Contains(output, "GLOG:") ||
		!strings.Contains(output, "Glog info message") {
		t.Errorf("Glog info message missing or incorrect: %s", output)
	}
}

func TestGlogWithLevel(t *testing.T) {
	setupGlog()

	// Create a logger using glog.V(level).Info for different log levels
	logger := &fipstls.DefaultLogger{
		Prefix: "GLOG:",
		Level:  fipstls.LogLevelDebug, // Allow all levels
		LoggerFunc: func(format string, args ...any) {
			message := fmt.Sprintf(format, args...)
			if strings.Contains(message, "ERROR:") {
				glog.Error(message)
			} else if strings.Contains(message, "INFO:") {
				glog.Info(message)
			} else if strings.Contains(message, "DEBUG:") {
				glog.V(1).Info(message)
			}
		},
	}

	output := captureOutput(func() {
		logger.Logf(fipstls.LogLevelErr, "Critical error")
		logger.Logf(fipstls.LogLevelInfo, "Important information")
		logger.Logf(fipstls.LogLevelDebug, "Verbose debugging info")
		glog.Flush()
	})
	t.Logf("Captured output: %s", output)

	// Check error and info logs
	if !strings.Contains(output, "ERROR:") || !strings.Contains(output, "Critical error") {
		t.Errorf("Glog error level message missing: %s", output)
	}

	if !strings.Contains(output, "INFO:") || !strings.Contains(output, "Important information") {
		t.Errorf("Glog info level message missing: %s", output)
	}
}

func TestGlogGrpcDial(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	lis, cleanupSrv := testutils.NewGrpcTestServer(t)
	defer cleanupSrv()

	addr := lis.Addr().String()
	t.Logf("Server listening on: %s", addr)

	t.Log("Creating new DialFn")
	logger := &fipstls.DefaultLogger{
		Prefix:     "GLOG:",
		Level:      fipstls.LogLevelInfo,
		LoggerFunc: glog.Infof,
	}
	dialFn := fipstls.NewDialContext(&fipstls.Config{CaFile: testutils.CertPath},
		fipstls.WithLogger(logger))

	output := captureOutput(func() {
		rawConn, err := dialFn(context.Background(), addr)
		if err != nil {
			t.Fatalf("Direct dial failed: %v", err)
		}
		rawConn.Close()
		glog.Flush()
	})

	t.Logf("Captured output: %s", output)

	// Verify glog received our messages
	if !strings.Contains(output, "INFO:") || !strings.Contains(output, "FIPS Mode") {
		t.Errorf("Glog info level message missing: %s", output)
	}
}
