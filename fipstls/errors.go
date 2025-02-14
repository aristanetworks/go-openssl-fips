package fipstls

import (
	"errors"
	"io"
	"net"
	"os"
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

	case libssl.SSL_ERROR_ZERO_RETURN:
		// Nothing else to do
		return io.EOF

	case libssl.SSL_ERROR_WANT_READ, libssl.SSL_ERROR_WANT_WRITE:
		// Temporary error
		opErr = &net.OpError{
			Op:   op,
			Net:  addr.Network(),
			Addr: addr,
			Err:  os.ErrDeadlineExceeded,
		}

	case libssl.SSL_ERROR_SYSCALL:
		// Permanent error - connection will be closed
		opErr = &net.OpError{
			Op:   op,
			Net:  addr.Network(),
			Addr: addr,
			Err:  syscall.ESHUTDOWN,
		}

	default:
		// Permanent error - connection will be closed
		opErr = &net.OpError{
			Op:   op,
			Net:  addr.Network(),
			Addr: addr,
			Err:  sslErr,
		}
	}
	return opErr
}
