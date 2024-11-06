package libssl

import (
	"fmt"
)

// SSLError represents an error returned by an OpenSSL function.
type SSLError struct {
	Code    int
	Message string
	Reason  string
}

// Error implements the error interface.
func (e *SSLError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s: error code %d (%s)", e.Reason, e.Code, e.Message)
	}
	return fmt.Sprintf("SSL error %d (%s)", e.Code, e.Message)
}

// newSSLError creates a new SSLError.
func newSSLError(reason string, code int) *SSLError {
	var message string
	switch code {
	case SSL_ERROR_NONE:
		message = "SSL_ERROR_NONE"
	case SSL_ERROR_SSL:
		message = "SSL_ERROR_SSL"
	case SSL_ERROR_WANT_READ:
		message = "SSL_ERROR_WANT_READ"
	case SSL_ERROR_WANT_WRITE:
		message = "SSL_ERROR_WANT_WRITE"
	case SSL_ERROR_WANT_X509_LOOKUP:
		message = "SSL_ERROR_WANT_X509_LOOKUP"
	case SSL_ERROR_SYSCALL:
		message = "SSL_ERROR_SYSCALL"
	case SSL_ERROR_ZERO_RETURN:
		message = "SSL_ERROR_ZERO_RETURN"
	case SSL_ERROR_WANT_CONNECT:
		message = "SSL_ERROR_WANT_CONNECT"
	case SSL_ERROR_WANT_ACCEPT:
		message = "SSL_ERROR_WANT_ACCEPT"
	default:
		message = "Unknown SSL error"
	}
	return &SSLError{Code: code, Message: message, Reason: reason}
}
