package ossl

import (
	"context"
	"net"
	"sync"
	"syscall"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// SSL represents a single SSL connection. It inherits configuration options from [SSLContext].
type SSL struct {
	ssl        *libssl.SSL
	closeOnce  sync.Once
	closeErr   error
	closed     bool
	sockfd     int
	rawConn    net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
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

// DialBIO will create a new BIO fd and connect to the host. It can be either blocking (mode=0) or
// non-blocking (mode=1).
func (s *SSL) DialBIO(ctx context.Context, addr string, family, mode int) error {
	if s.closed {
		return s.closeErr
	}
	if err := s.dialBIO(ctx, addr, family, mode); err != nil {
		return err
	}
	if err := s.setAddrInfo(); err != nil {
		return err
	}
	return nil
}

func (s *SSL) dialBIO(ctx context.Context, addr string, family, mode int) error {
	if s.closed {
		return s.closeErr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	errCh := make(chan error)
	go func() {
		errCh <- runWithLockedOSThread(func() error {
			return libssl.SSLDialHost(s.ssl, host, port, family, mode)
		})
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// dialTCP will dial a TCP connection using golang's [net.Dial] and pass the fd to SSL.
func (s *SSL) dialTCP(ctx context.Context, addr string) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
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

// setAddrInfo will return the local and remote addresses of the [SSL] connection.
func (s *SSL) setAddrInfo() (err error) {
	if s.closed {
		return s.closeErr
	}
	s.sockfd, err = libssl.SSLGetFd(s.ssl)
	sockname, err := syscall.Getsockname(s.sockfd)
	if err != nil {
		return err
	}
	peername, err := syscall.Getpeername(s.sockfd)
	if err != nil {
		return err
	}
	s.localAddr, s.remoteAddr = sockaddrToNetAddr(sockname), sockaddrToNetAddr(peername)
	return nil
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
	return s.localAddr
}

func (s *SSL) RemoteAddr() net.Addr {
	return s.remoteAddr
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
