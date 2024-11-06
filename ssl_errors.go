package client

import (
	"errors"
	"io"
	"log"
	"net"
	"syscall"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

var (
	ErrNoLibSslInit      = errors.New("ossl: libssl was not intialized with ossl.Init")
	ErrLoadLibSslFailed  = errors.New("ossl: libssl failed to load")
	ErrInvalidOption     = errors.New("ossl: invalid option")
	ErrInvalidSSLContext = errors.New("ossl: invalid SSLContext")
)

// Different types of SSL errors we need to handle
type sslError struct {
	err       error
	timeout   bool // Was this caused by a deadline?
	temporary bool // Can the operation be retried?
}

func (e *sslError) Error() string   { return e.err.Error() }
func (e *sslError) Timeout() bool   { return e.timeout }
func (e *sslError) Temporary() bool { return e.temporary }

// NewSSLConnError converts SSL errors to appropriate net.OpError with syscall errors
func NewSSLConnError(op string, addr string, err error) error {
	log.Println("Got SSL error", err)
	sslErr, ok := err.(*libssl.SSLError)
	if !ok {
		return err
	}

	var opErr *net.OpError
	switch sslErr.Code {
	case libssl.SSL_ERROR_NONE:
		return nil

	case libssl.SSL_ERROR_WANT_READ:
		opErr = &net.OpError{
			Op:  op,
			Net: "tcp",
			// Addr: addr,
			Err: syscall.EAGAIN,
		}

	case libssl.SSL_ERROR_WANT_WRITE:
		opErr = &net.OpError{
			Op:  op,
			Net: "tcp",
			// Addr: addr,
			Err: syscall.EAGAIN,
		}

	case libssl.SSL_ERROR_ZERO_RETURN:
		opErr = &net.OpError{
			Op:  op,
			Net: "tcp",
			// Addr: addr,
			Err: io.EOF,
		}

	case libssl.SSL_ERROR_SYSCALL:
		opErr = &net.OpError{
			Op:  op,
			Net: "tcp",
			// Addr: addr,
			Err: syscall.ECONNRESET,
		}

	default:
		// Permanent error - connection will be closed
		opErr = &net.OpError{
			Op:  op,
			Net: "tcp",
			// Addr: addr,
			Err: sslErr,
		}
	}
	defer log.Println("Returning net.OpError", opErr)
	return opErr
}
