package ossl

import (
	"net"
	"sync"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

// SSL represents a single SSL connection. It inherits configuration options from [SSLContext].
type SSL struct {
	ssl       *libssl.SSL
	bio       *BIO
	closeOnce sync.Once
	closeErr  error
	closed    bool
}

// NewSSL creates an [SSL] object using [SSLContext]. [SSL] is used for creating
// a single TLS connection.
func NewSSL(ctx *SSLContext, bio *BIO) (*SSL, error) {
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
		if err := libssl.SSLConfigureBIO(s, bio.bio, bio.hostname); err != nil {
			libssl.SSLFree(s)
			return err
		}
		ssl = &SSL{
			ssl: s,
			bio: bio,
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ssl, nil
}

// FD returns the socket file descriptor used by [SSL].
func (s *SSL) FD() int {
	return s.bio.FD()
}

// CloseFD will close the socket file descriptor used by [SSL].
func (s *SSL) CloseFD() error {
	if s.closed {
		return s.closeErr
	}
	return s.bio.CloseFD()
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
	s.closeOnce.Do(func() {
		s.closeErr = libssl.SSLFree(s.ssl)
		s.closed = true
	})
	return s.closeErr
}
