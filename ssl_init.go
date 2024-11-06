package client

import (
	"errors"

	"github.com/golang-fips/openssl/v2/internal/libssl"
)

var (
	libsslInit bool
)

// Init should be called before any calls into libssl
func Init(version string) error {
	if version == "" {
		version = libssl.GetVersion()
	}
	if err := libssl.Init(version); err != nil {
		return errors.Join(ErrLoadLibSslFailed, err)
	}
	libsslInit = true
	return nil
}
