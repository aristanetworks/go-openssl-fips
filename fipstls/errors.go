package fipstls

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

var (
	ErrNoLibSslInit     = errors.New("fipstls: libssl was not initialized with fipstls.Init")
	ErrLoadLibSslFailed = errors.New("fipstls: libssl failed to load")
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
