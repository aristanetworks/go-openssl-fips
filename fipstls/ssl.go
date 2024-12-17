package fipstls

import (
	"net"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

// SSL represents a single SSL connection. It inherits configuration options
// from [Context].
type SSL struct {
	ssl    *libssl.SSL
	bio    *BIO
	closed bool
	closer Closer
}

// NewSSL creates an [SSL] object using [Context]. [SSL] is used for creating
// a single TLS connection.
func NewSSL(ctx *Context, bio *BIO) (s *SSL, err error) {
	if !libsslInit {
		return nil, ErrNoLibSslInit
	}
	s = &SSL{closer: noopCloser{}}
	if err := runWithLockedOSThread(func() error {
		s.ssl, err = libssl.NewSSL(ctx.Ctx())
		if err != nil {
			libssl.SSLFree(s.ssl)
			return err
		}
		if err := s.withBIO(bio); err != nil {
			libssl.SSLFree(s.ssl)
			return err
		}
		return nil
	}); err != nil {
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

func (s *SSL) withBIO(b *BIO) error {
	s.bio = b
	if err := libssl.SSLConfigureBIO(s.ssl, b.BIO(), b.Hostname()); err != nil {
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

// CloseFD will close the socket file descriptor used by [SSL].
func (s *SSL) CloseFD() error {
	if s.closed {
		return s.closer.Err()
	}
	return s.bio.CloseFD()
}

// Read will read bytes into the buffer from the [SSL] connection.
func (s *SSL) Read(b []byte) (int, error) {
	if s.closer.Err() != nil {
		return 0, s.closer.Err()
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

// Shutdown will send a close-notify alert to the peer to gracefully shutdown
// the [SSL] connection.
func (s *SSL) Shutdown() error {
	if s.closed {
		return s.closer.Err()
	}
	return runWithLockedOSThread(func() error {
		err := libssl.SSLShutdown(s.ssl)
		if err != nil {
			return err
		}
		return nil
	})
}

// GetShutdownState returns the shutdown state of the [SSL] connection.
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

// Close frees the [libssl.SSL] C object allocated by [SSL].
func (s *SSL) Close() error {
	return s.closer.Close()
}
