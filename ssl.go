package ossl

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// SSL represents a single SSL connection. It inherits configuration options from [SSLContext].
type SSL struct {
	ssl      *libssl.SSL
	freeOnce sync.Once
	freeErr  error
	sockfd   int
}

// NewSSL creates an [SSL] object using [SSLContext]. [SSL] is used for creating
// a single TLS connection.
func NewSSL(sslCtx *SSLContext, c *Config) (*SSL, error) {
	if err := Init(c.LibsslVersion); err != nil {
		return nil, err
	}
	var ssl *SSL
	if err := runWithLockedOSThread(func() error {
		s, err := libssl.NewSSL(sslCtx.ctx)
		if err != nil {
			libssl.SSLFree(s)
			return err
		}
		ssl = &SSL{ssl: s}
		return nil
	}); err != nil {
		return nil, err
	}
	return ssl, nil
}

// DialHost will create a new BIO fd and connect to the host. It can be either blocking (mode=0) or
// non-blocking (mode=1).
func (s *SSL) DialHost(host, port string, family, ioMode int) error {
	return runWithLockedOSThread(func() error {
		return libssl.SSLDialHost(s.ssl, host, port, family, ioMode)
	})
}

// GetAddrInfo will return the local and remote addresses of the [SSL] connection.
func (s *SSL) GetAddrInfo() (local net.Addr, remote net.Addr, err error) {
	s.sockfd, err = libssl.SSLGetFd(s.ssl)
	sockname, err := syscall.Getsockname(s.sockfd)
	if err != nil {
		return nil, nil, err
	}
	peername, err := syscall.Getpeername(s.sockfd)
	if err != nil {
		return nil, nil, err
	}
	return sockaddrToNetAddr(sockname), sockaddrToNetAddr(peername), nil
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

// CloseFD will close the [SSL] file descriptor using syscall.Close.
func (s *SSL) CloseFD() error {
	return syscall.Close(s.sockfd)
}

// Read will read bytes into the buffer from the [SSL] connection.
func (s *SSL) Read(b []byte) (int, error) {
	var readBytes []byte
	var numBytes int
	if err := runWithLockedOSThread(func() error {
		r, n, err := libssl.SSLReadEx(s.ssl, int64(len(b)))
		if err != nil {
			return err
		}
		readBytes = r
		numBytes = n
		return nil
	}); err != nil {
		return numBytes, err
	}
	copy(b, readBytes[:numBytes])
	return numBytes, nil
}

// Write will write bytes from the buffer to the [SSL] connection.
func (s *SSL) Write(b []byte) (int, error) {
	var numBytes int
	if err := runWithLockedOSThread(func() error {
		n, err := libssl.SSLWriteEx(s.ssl, b)
		if err != nil {
			return err
		}
		numBytes = n
		return nil
	}); err != nil {
		return numBytes, err
	}
	return numBytes, nil
}

// Close will send a close-notify alert to the peer to gracefully shutdown the [SSL] connection.
func (s *SSL) Close() error {
	return runWithLockedOSThread(func() error {
		err := libssl.SSLShutdown(s.ssl)
		if err != nil {
			return err
		}
		return nil
	})
}

// Free will free the C memory allocated by [SSL]. [SSL] should not be used after calling free.
func (s *SSL) Free() error {
	s.freeOnce.Do(func() {
		s.freeErr = libssl.SSLFree(s.ssl)
	})
	return s.freeErr
}
