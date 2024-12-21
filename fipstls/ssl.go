package fipstls

import (
	"net"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// SSL represents a single SSL connection. It inherits configuration options
// from [SSLContext].
type SSL struct {
	ssl    *libssl.SSL
	bio    *BIO
	closed bool
	closer Closer
}

// NewSSL creates an [SSL] object using [SSLContext]. [SSL] is used for creating
// a single TLS connection.
func NewSSL(ctx *SSLContext, bio *BIO) (s *SSL, err error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	s = &SSL{closer: noopCloser{}}
	s.ssl, err = libssl.NewSSL(ctx.Ctx())
	if err != nil {
		libssl.SSLFree(s.ssl)
		return nil, err
	}
	if err := s.configureBIO(bio); err != nil {
		libssl.SSLFree(s.ssl)
		return nil, err
	}
	s.closer = &onceCloser{
		closeFunc: func() error {
			s.closed = true
			return libssl.SSLFree(s.ssl)
		},
	}
	return s, nil
}

func (s *SSL) configureBIO(b *BIO) error {
	s.bio = b
	if err := libssl.SSLConfigureBIO(s.ssl, b.BIO(), b.Hostname()); err != nil {
		return err
	}
	return nil
}

// Connect initiates a TLS handshake with the peer.
func (s *SSL) Connect() error {
	err := libssl.SSLConnect(s.ssl)
	if err == nil {
		return err
	}
	if err := libssl.SSLGetVerifyResult(s.ssl); err != nil {
		return err
	}
	return nil
}

// SSL returns a pointer to the underlying [libssl.SSL] C object.
func (s *SSL) SSL() *libssl.SSL {
	return s.ssl
}

// FD returns the socket file descriptor used by [SSL] C object.
func (s *SSL) FD() int {
	return s.bio.FD()
}

// Read will read bytes into the buffer from the [SSL] connection.
func (s *SSL) Read(b []byte) (int, error) {
	if s.closer.Err() != nil {
		return 0, s.closer.Err()
	}
	r, n, err := libssl.SSLReadEx(s.ssl, int64(len(b)))
	if err != nil {
		if err := libssl.SSLGetVerifyResult(s.ssl); err != nil {
			return n, err
		}
		return n, err
	}
	copy(b, r[:n])
	return n, nil
}

// LocalAddr returns the local address if known.
func (s *SSL) LocalAddr() net.Addr {
	return s.bio.LocalAddr()
}

// RemoteAddr returns the peer address if known.
func (s *SSL) RemoteAddr() net.Addr {
	return s.bio.RemoteAddr()
}

// Write will write bytes from the buffer to the [SSL] connection.
func (s *SSL) Write(b []byte) (int, error) {
	if s.closed {
		return 0, s.closer.Err()
	}
	return libssl.SSLWriteEx(s.ssl, b)
}

// Shutdown will send a close-notify alert to the peer to gracefully shutdown
// the [SSL] connection.
func (s *SSL) Shutdown() error {
	if s.closed {
		return s.closer.Err()
	}
	return libssl.SSLShutdown(s.ssl)
}

// GetShutdownState returns the shutdown state of the [SSL] connection.
func (s *SSL) GetShutdownState() int {
	if s.closed {
		return -1
	}
	return libssl.SSLGetShutdown(s.ssl)
}

// Close frees the [libssl.SSL] C object allocated for [SSL].
func (s *SSL) Close() error {
	return s.closer.Close()
}
