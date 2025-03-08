//go:build static

// Package libssl provides access to OpenSSL TLS methods.
package libssl

// #cgo CFLAGS: -I/usr/include -Wno-deprecated-declarations -Wno-discarded-qualifiers
// #cgo LDFLAGS: -lssl -lcrypto
// #include "static_golibssl.h"
import "C"
import (
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

var (
	vMajor = uint(C.OPENSSL_VERSION_MAJOR)
	vMinor = uint(C.OPENSSL_VERSION_MINOR)
	vPatch = uint(C.OPENSSL_VERSION_PATCH)
)

// Init does nothing when we are statically-linking
func Init(file string) error {
	return nil
}

func utoa(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}

func errUnsupportedVersion() error {
	return errors.New(
		"openssl: OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch),
	)
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

func VersionText() string {
	return C.GoString(C.OpenSSL_version(0))
}

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")
)

func FIPS() bool {
	switch vMajor {
	case 3:
		if C.EVP_default_properties_is_fips_enabled(nil) == 0 {
			return false
		}
		return C.OSSL_PROVIDER_available(nil, providerNameFips) == 1
	default:
		panic(errUnsupportedVersion())
	}
}

// SetFIPS enables or disables FIPS mode.
//
// For OpenSSL 3, the `fips` provider is loaded if enabled is true,
// else the `default` provider is loaded.
func SetFIPS(enabled bool) error {
	var mode C.int
	if enabled {
		mode = C.int(1)
	} else {
		mode = C.int(0)
	}
	switch vMajor {
	case 3:
		var provName *C.char
		if enabled {
			provName = providerNameFips
		} else {
			provName = providerNameDefault
		}
		// Check if there is any provider that matches props.
		if C.OSSL_PROVIDER_available(nil, provName) != 1 {
			// If not, fallback to provName provider.
			if C.OSSL_PROVIDER_load(nil, provName) == nil {
				return NewOpenSSLError("OSSL_PROVIDER_try_load")
			}
			// Make sure we now have a provider available.
			if C.OSSL_PROVIDER_available(nil, provName) != 1 {
				return fail("SetFIPS(" + strconv.FormatBool(enabled) + ") not supported")
			}
		}
		if C.EVP_default_properties_enable_fips(nil, mode) != 1 {
			return NewOpenSSLError("openssl: EVP_default_properties_enable_fips")
		}
		return nil
	default:
		panic(errUnsupportedVersion())
	}
}

// noescape hides a pointer from escape analysis. noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input. noescape is inlined and currently
// compiles down to zero instructions.
// USE CAREFULLY!
//
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

var zero byte

// addr converts p to its base addr, including a noescape along the way.
// If p is nil, addr returns a non-nil pointer, so that the result can always
// be dereferenced.
//
//go:nosplit
func addr(p []byte) *byte {
	if len(p) == 0 {
		return &zero
	}
	return (*byte)(noescape(unsafe.Pointer(&p[0])))
}

func NewOpenSSLError(msg string) error {
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):")
	for {
		var (
			e    C.ulong
			file *C.char
			line C.int
		)
		switch vMajor {
		case 1:
			e = C.ERR_get_error_line(&file, &line)
		case 3:
			e = C.ERR_get_error_all(&file, &line, nil, nil, nil)
		default:
			panic(errUnsupportedVersion())
		}
		if e == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		C.ERR_error_string_n(e, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		b.WriteString(string(buf[:]) + "\n\t" + C.GoString(file) + ":" + strconv.Itoa(int(line)))
	}
	return errors.New(b.String())
}

var unknownFile = "<go code>\000"

func CheckLeaks() {
	C.do_leak_check()
}
