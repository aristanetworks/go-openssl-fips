package libssl

import (
	"fmt"
	"time"
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

// RetryableFunc represents a function that can be retried.
type RetryableFunc func() ([]byte, int, error)

// Retry executes the given RetryableFunc with exponential backoff and a timeout.
func Retry(fn RetryableFunc, timeout time.Duration) ([]byte, int, error) {
	startTime := time.Now()
	attempt := 0
	sleepTime := 10 * time.Millisecond // Initial sleep time

	for {
		b, r, err := fn()
		if err == nil {
			return b, r, nil
		}

        sslErr, ok := err.(*SSLError)
        if ok && !sslErr.IsRetryable() {
            return b, r, err
        }

		attempt++
		elapsed := time.Since(startTime)
		if elapsed > timeout {
			return b, r, fmt.Errorf("operation timed out after %v: %w", elapsed, err)
		}

		time.Sleep(sleepTime)
		sleepTime *= 2 // Exponential backoff
		if sleepTime > 1*time.Second {
			sleepTime = 1 * time.Second // Cap the sleep time
		}
	}
}

// IsRetryable returns true if the SSL error is retryable.
// TODO: need to handle io failures similar to:
// https://github.com/openssl/openssl/blob/5091aadc223315ce115ee12f62df2af173bf5efb/demos/guide/tls-client-non-block.c#L138
func (e *SSLError) IsRetryable() bool {
	switch e.Code {
	case SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE,
		SSL_ERROR_WANT_X509_LOOKUP, SSL_ERROR_WANT_CONNECT,
		SSL_ERROR_WANT_ACCEPT:
		return true
	default:
		return false
	}
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
