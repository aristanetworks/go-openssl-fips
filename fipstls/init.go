package fipstls

import (
	"errors"
	"sync"

	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/libssl"
)

var (
	libsslInit bool
)

// Init should be called before any calls into libssl. If the version string is empty, it will pick
// the highest libssl.so version automatically.
func Init(version string) error {
	if libsslInit {
		return nil
	}
	if err := libssl.Init(version); err != nil {
		return errors.Join(ErrLoadLibSslFailed, err)
	}
	libsslInit = true
	return nil
}

// FIPSMode returns true if FIPS mode is enabled in the dynamically loaded libssl.so, and false
// otherwise.
func FIPSMode() bool {
	if !libsslInit {
		return false
	}
	return libssl.FIPS()
}

// SetFIPS can be used to enable FIPS mode in the dynamically loaded libssl.so.
func SetFIPS(enabled bool) error {
	if !libsslInit {
		return ErrNoLibSslInit
	}
	return libssl.SetFIPS(enabled)
}

// Version returns the dynamically loaded libssl.so version, or an empty string otherwise.
var Version = sync.OnceValue(func() string {
	if !libsslInit {
		return ErrNoLibSslInit.Error()
	}
	return libssl.VersionText()
})

// ProviderInfo returns the name, version, and buildinfo of the first FIPS-capable provider.
var ProviderInfo = sync.OnceValue(func() string {
	if !libsslInit {
		return ErrNoLibSslInit.Error()
	}
	info, err := libssl.GetFipsProviderInfo()
	if err != nil {
		return err.Error()
	}
	return info
})
