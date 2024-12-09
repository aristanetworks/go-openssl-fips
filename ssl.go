package ossl

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

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
		s, err := newSsl(sslCtx)
		if err != nil {
			libssl.SSLFree(s)
			return err
		}
		ssl = &SSL{ssl: s}
		if err := ssl.apply(c); err != nil {
			libssl.SSLFree(s)
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ssl, nil
}

// DialHost will create a new BIO fd and connect to the host, can be either blocking (ioMode=0) or
// non-blocking (ioMode=1).
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

func (s *SSL) CloseFD() error {
	// Close the file descriptor using syscall.Close
	return syscall.Close(s.sockfd)
}

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

func (s *SSL) Write(b []byte) (int, error) {
	var written int
	if err := runWithLockedOSThread(func() error {
		n, err := libssl.SSLWriteEx(s.ssl, b)
		if err != nil {
			return err
		}
		written = n
		return nil
	}); err != nil {
		return written, err
	}
	return written, nil
}

func (s *SSL) Close() error {
	return runWithLockedOSThread(func() error {
		err := libssl.SSLShutdown(s.ssl)
		if err != nil {
			return err
		}
		return nil
	})
}

// Free will free the [libssl.SSL] C allocated object.
func (s *SSL) Free() error {
	s.freeOnce.Do(func() {
		s.freeErr = libssl.SSLFree(s.ssl)
	})
	return s.freeErr
}

func newSsl(sslCtx *SSLContext) (*libssl.SSL, error) {
	ssl, err := libssl.NewSSL(sslCtx.ctx)
	if err != nil {
		return nil, err
	}
	return ssl, nil
}

func (s *SSL) apply(c *Config) error {
	// TODO: Apply certificate verification flags
	// var x509Flags int64
	// if c.CertificateChecks&X509CheckTimeValidity != 0 {
	// 	x509Flags |= libssl.X509_V_FLAG_USE_CHECK_TIME
	// }
	// if c.CertificateChecks&X509CheckCRL != 0 {
	// 	x509Flags |= libssl.X509_V_FLAG_CRL_CHECK
	// }
	// if c.CertificateChecks&X509CheckCRLAll != 0 {
	// 	x509Flags |= libssl.X509_V_FLAG_CRL_CHECK_ALL
	// }
	// if c.CertificateChecks&X509StrictMode != 0 {
	// 	x509Flags |= libssl.X509_V_FLAG_X509_STRICT
	// }
	// if c.CertificateChecks&X509AllowPartialChains != 0 {
	// 	x509Flags |= libssl.X509_V_FLAG_PARTIAL_CHAIN
	// }
	// if c.CertificateChecks&X509TrustedFirst != 0 {
	// 	x509Flags |= libssl.X509_V_FLAG_TRUSTED_FIRST
	// }

	// verifyParam, err := libssl.SSLGet0Param(s.ssl)
	// if err != nil {
	// 	return err
	// }
	// if err := libssl.X509VerifyParamSetFlags(verifyParam, x509Flags); err != nil {
	// 	return fmt.Errorf("failed to set verify flags: %w", err)
	// }

	return nil
}
