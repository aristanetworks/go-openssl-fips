package ossl

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// SSL represents a single SSL connection. It inherits configuration options from [SSLContext].
type SSL struct {
	ssl       *libssl.SSL
	closeOnce sync.Once
	closeErr  error
	closed    bool
	sockfd    int
	rawConn   net.Conn
}

// NewSSL creates an [SSL] object using [SSLContext]. [SSL] is used for creating
// a single TLS connection.
func NewSSL(ctx *SSLContext) (*SSL, error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	var ssl *SSL
	if err := runWithLockedOSThread(func() error {
		s, err := libssl.NewSSL(ctx.ctx)
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

func (s *SSL) SetFd(fd int) error {
	return libssl.SetSSLFd(s.ssl, fd)
}

// DialHost will create a new BIO fd and connect to the host. It can be either blocking (mode=0) or
// non-blocking (mode=1).
func (s *SSL) DialHost(addr string, family, ioMode int) error {
	if s.closed {
		return s.closeErr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	return runWithLockedOSThread(func() error {
		return libssl.SSLDialHost(s.ssl, host, port, family, ioMode)
	})
}

func (s *SSL) Dial(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	// Get the raw file descriptor (this is a duplicate fd)
	file, _ := conn.(*net.TCPConn).File()
	fd := int(file.Fd())
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if err := libssl.SSLConfigure(s.ssl, host, port, fd); err != nil {
		return err
	}
	s.rawConn = conn
	s.sockfd = fd
	return nil
}

// GetAddrInfo will return the local and remote addresses of the [SSL] connection.
func (s *SSL) GetAddrInfo() (local net.Addr, remote net.Addr, err error) {
	if s.closed {
		return nil, nil, s.closeErr
	}
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
	if s.closed {
		return s.closeErr
	}
	return syscall.Close(s.sockfd)
}

// Read will read bytes into the buffer from the [SSL] connection.
func (s *SSL) Read(b []byte) (int, error) {
	if s.closeErr != nil {
		return 0, s.closeErr
	}
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

func (s *SSL) LocalAddr() net.Addr {
	return s.rawConn.LocalAddr()
}

func (s *SSL) RemoteAddr() net.Addr {
	return s.rawConn.RemoteAddr()
}

func (s *SSL) SetDeadline(t time.Time) error {
	return s.rawConn.SetDeadline(t)
}

func (s *SSL) SetReadDeadline(t time.Time) error {
	return s.rawConn.SetReadDeadline(t)
}

func (s *SSL) SetWriteDeadline(t time.Time) error {
	return s.rawConn.SetWriteDeadline(t)
}

// Write will write bytes from the buffer to the [SSL] connection.
func (s *SSL) Write(b []byte) (int, error) {
	if s.closed {
		return 0, s.closeErr
	}
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

// Shutdown will send a close-notify alert to the peer to gracefully shutdown the [SSL] connection.
func (s *SSL) Shutdown() error {
	if s.closed {
		return s.closeErr
	}
	return runWithLockedOSThread(func() error {
		err := libssl.SSLShutdown(s.ssl)
		if err != nil {
			return err
		}
		return nil
	})
}

// GetShutdownState
func (s *SSL) GetShutdownState() int {
	if s.closed {
		return -1
	}
	var state int
	runWithLockedOSThread(func() error {
		state = libssl.SSLGetShutdown(s.ssl)
		return nil
	})
	return state
}

// Close will Close the C memory allocated by [SSL]. [SSL] should not be used after calling Close.
func (s *SSL) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = libssl.SSLFree(s.ssl)
		s.closed = true
	})
	return s.closeErr
}
