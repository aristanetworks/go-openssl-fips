package ossl

import (
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// runWithLockedOSThread ensures the given function executes with the goroutine locked to an OS thread.
func runWithLockedOSThread(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	libssl.SSLClearError()
	return fn()
}

func sockaddrToNetAddr(sa syscall.Sockaddr) net.Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: int(sa.Port),
		}
	case *syscall.SockaddrInet6:
		return &net.TCPAddr{
			IP:   sa.Addr[:],
			Port: int(sa.Port),
			Zone: zoneToString(int(sa.ZoneId)),
		}
	case *syscall.SockaddrUnix:
		return &net.UnixAddr{
			Name: sa.Name,
			Net:  "unix",
		}
	default:
		return nil
	}
}

func zoneToString(zone int) string {
	if zone == 0 {
		return ""
	}
	if ifi, err := net.InterfaceByIndex(zone); err == nil {
		return ifi.Name
	}
	return fmt.Sprintf("%d", zone)
}
