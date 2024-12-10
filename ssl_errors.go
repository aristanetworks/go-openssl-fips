package ossl

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/aristanetworks/go-openssl-fips/ossl/internal/libssl"
)

var (
	ErrNoLibSslInit      = errors.New("ossl: libssl was not initialized with ossl.Init")
	ErrLoadLibSslFailed  = errors.New("ossl: libssl failed to load")
	ErrInvalidOption     = errors.New("ossl: invalid option")
	ErrInvalidSSLContext = errors.New("ossl: invalid SSLContext")
	ErrShutdown          = errors.New("ossl: protocol is shutdown")
)

// newConnError converts SSL errors to appropriate net.OpError with syscall errors
func newConnError(op string, addr net.Addr, err error) error {
	sslErr, ok := err.(*libssl.SSLError)
	if !ok {
		return err
	}

	var opErr *net.OpError
	switch sslErr.Code {
	case libssl.SSL_ERROR_NONE:
		return nil

	case libssl.SSL_ERROR_WANT_READ, libssl.SSL_ERROR_WANT_WRITE:
		opErr = &net.OpError{
			Op:   op,
			Net:  "tcp",
			Addr: addr,
			Err:  syscall.EAGAIN,
		}

	case libssl.SSL_ERROR_ZERO_RETURN:
		opErr = &net.OpError{
			Op:   op,
			Net:  "tcp",
			Addr: addr,
			Err:  io.EOF,
		}

	case libssl.SSL_ERROR_SYSCALL:
		opErr = &net.OpError{
			Op:   op,
			Net:  "tcp",
			Addr: addr,
			Err:  syscall.ECONNRESET,
		}

	default:
		// Permanent error - connection will be closed
		opErr = &net.OpError{
			Op:   op,
			Net:  "tcp",
			Addr: addr,
			Err:  sslErr,
		}
	}
	return opErr
}
