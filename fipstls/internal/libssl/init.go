//go:build !cmd_go_bootstrap

package libssl

// #include "golibssl.h"
import "C"
import (
	"errors"
)

// opensslInit loads and initialize OpenSSL.
// If successful, it returns the major and minor OpenSSL version
// as reported by the OpenSSL API.
//
// See Init() for details about file.
func opensslInit(file string) (major, minor, patch uint, err error) {
	// Load the OpenSSL shared library using dlopen.
	handle, err := dlopen(file)
	if err != nil {
		return 0, 0, 0, err
	}

	// Retrieve the loaded OpenSSL version and check if it is supported.
	// Notice that major and minor could not match with the version parameter
	// in case the name of the shared library file differs from the OpenSSL
	// version it contains.
	imajor := int(C.go_openssl_version_major(handle))
	iminor := int(C.go_openssl_version_minor(handle))
	ipatch := int(C.go_openssl_version_patch(handle))
	if imajor < 0 || iminor < 0 || ipatch < 0 {
		return 0, 0, 0, errors.New("openssl: can't retrieve OpenSSL version")
	}
	major, minor, patch = uint(imajor), uint(iminor), uint(ipatch)
	var supported bool
	switch major {
	case 1:
		supported = minor == 1
	case 3:
		// OpenSSL guarantees API and ABI compatibility within the same major version since OpenSSL 3.
		supported = true
	}
	if !supported {
		return 0, 0, 0, errUnsupportedVersion()
	}

	// Load the OpenSSL functions.
	// See libssl_shim.h for the complete list of supported functions.
	C.go_openssl_load_functions(handle, C.uint(major), C.uint(minor), C.uint(patch))

	// Initialize OpenSSL.
	flags := C.uint64_t(C.GO_OPENSSL_INIT_ADD_ALL_CIPHERS | C.GO_OPENSSL_INIT_ADD_ALL_DIGESTS | C.GO_OPENSSL_INIT_LOAD_CONFIG | C.GO_OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
	if C.go_openssl_OPENSSL_init_ssl(flags, nil) != 1 {
		return 0, 0, 0, fail("openssl: init ssl")
	}
	return major, minor, patch, nil
}
