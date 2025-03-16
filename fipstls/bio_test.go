package fipstls_test

import (
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

func TestInvalidNetwork(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()
	invalidNet := "tcp420"
	_, err := fipstls.NewBIO("example.com:0", invalidNet, fipstls.SOCK_NONBLOCK)
	t.Logf("NewBIO() error = %v", err)
	if err != nil && !errors.Is(err, net.UnknownNetworkError(invalidNet)) {
		t.Errorf("Expected UnknownNetworkError for network %q, got %T: %v", invalidNet, err, err)
	}

}

func newTestListener(t *testing.T) (string, io.Closer) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	return l.Addr().String(), l
}

func TestBIOString(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()

	addr, l := newTestListener(t)
	defer l.Close()

	bio, err := fipstls.NewBIO(addr, "tcp", fipstls.SOCK_NONBLOCK)
	if err != nil {
		t.Fatalf("Failed to create BIO: %v", err)
	}
	defer bio.Close()

	s := bio.String()
	// Verify it contains the expected parts
	if !strings.Contains(s, "local=") || !strings.Contains(s, "remote=") ||
		!strings.Contains(s, "conn=") {
		t.Errorf("BIO.String() = %q, doesn't contain expected parts", s)
	}
}

func TestNewBIO(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()

	tests := []struct {
		name    string
		addr    string
		network string
		mode    int
		wantErr bool
	}{
		{
			name:    "invalid address",
			addr:    "example.com", // missing port
			network: "tcp",
			mode:    fipstls.SOCK_NONBLOCK,
			wantErr: true,
		},
		{
			name:    "invalid network",
			addr:    "example.com:443",
			network: "invalid",
			mode:    fipstls.SOCK_NONBLOCK,
			wantErr: true,
		},
		{
			name:    "non-existent host",
			addr:    "nonexistent.example:443",
			network: "tcp",
			mode:    fipstls.SOCK_NONBLOCK,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fipstls.NewBIO(tt.addr, tt.network, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBIO() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	addr, l := newTestListener(t)
	defer l.Close()
	bio, err := fipstls.NewBIO(addr, "tcp", fipstls.SOCK_NONBLOCK)
	if err != nil {
		t.Errorf("NewBIO() with valid address error = %v", err)
		return
	}
	defer bio.Close()

	// Test the accessor methods
	if bio.FD() <= 0 {
		t.Errorf("NewBIO() created BIO with invalid FD: %d", bio.FD())
	}

	if bio.LocalAddr() == nil {
		t.Error("NewBIO() created BIO with nil LocalAddr")
	}

	if bio.RemoteAddr() == nil {
		t.Error("NewBIO() created BIO with nil RemoteAddr")
	}

	host, _, _ := net.SplitHostPort(addr)
	if bio.Hostname() != host {
		t.Errorf("BIO.Hostname() = %q, want %q", bio.Hostname(), host)
	}
}

func TestBIOMethods(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()

	addr, l := newTestListener(t)
	defer l.Close()
	bio, err := fipstls.NewBIO(addr, "tcp", fipstls.SOCK_NONBLOCK)
	if err != nil {
		t.Fatalf("Failed to create BIO: %v", err)
	}
	defer bio.Close()

	if bio.BIO() == nil {
		t.Error("BIO.BIO() returned nil")
	}

	if bio.FD() <= 0 {
		t.Errorf("BIO.FD() = %d, want > 0", bio.FD())
	}

	localAddr := bio.LocalAddr()
	if localAddr == nil {
		t.Error("BIO.LocalAddr() returned nil")
	} else {
		if _, ok := localAddr.(*net.TCPAddr); !ok {
			t.Errorf("BIO.LocalAddr() = %T, want *net.TCPAddr", localAddr)
		}
	}

	remoteAddr := bio.RemoteAddr()
	if remoteAddr == nil {
		t.Error("BIO.RemoteAddr() returned nil")
	} else {
		if _, ok := remoteAddr.(*net.TCPAddr); !ok {
			t.Errorf("BIO.RemoteAddr() = %T, want *net.TCPAddr", remoteAddr)
		}
	}

	host, _, _ := net.SplitHostPort(addr)
	if bio.Hostname() != host {
		t.Errorf("BIO.Hostname() = %q, want %q", bio.Hostname(), host)
	}
}

func TestBIOClose(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()

	addr, l := newTestListener(t)
	defer l.Close()
	bio, err := fipstls.NewBIO(addr, "tcp", fipstls.SOCK_NONBLOCK)
	if err != nil {
		t.Fatalf("Failed to create BIO: %v", err)
	}

	// Close the BIO
	if err := bio.Close(); err != nil {
		t.Errorf("BIO.Close() error = %v", err)
	}

	// Verify underlying resources are cleaned up
	if err := syscall.SetNonblock(bio.FD(), true); err == nil {
		t.Error("BIO.Close() didn't properly close the socket, still able to set non-blocking mode")
	}
}

func TestBIOCloseFD(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()

	addr, l := newTestListener(t)
	defer l.Close()
	bio, err := fipstls.NewBIO(addr, "tcp", fipstls.SOCK_NONBLOCK)
	if err != nil {
		t.Fatalf("Failed to create BIO: %v", err)
	}
	defer bio.Close()

	// Close just the file descriptor
	fd := bio.FD()
	if err := bio.CloseFD(); err != nil {
		t.Errorf("BIO.CloseFD() error = %v", err)
	}

	// Verify FD is closed
	if err := syscall.SetNonblock(fd, true); err == nil {
		t.Error("BIO.CloseFD() didn't properly close the socket FD")
	}
}

func TestBIONonBlocking(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	defer libssl.Reset()

	addr, l := newTestListener(t)
	defer l.Close()
	bio, err := fipstls.NewBIO(addr, "tcp", fipstls.SOCK_NONBLOCK)
	if err != nil {
		t.Fatalf("Failed to create non-blocking BIO: %v", err)
	}
	defer bio.Close()

	// Verify socket
	if bio.FD() <= 0 {
		t.Error("Non-blocking BIO has invalid FD")
	}
}
