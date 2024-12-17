//go:build !cmd_go_bootstrap

// Package libssl provides access to OpenSSL TLS methods.
package libssl

// #include "golibssl.h"
import "C"
import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

var (
	// vMajor and vMinor hold the major/minor OpenSSL version.
	// It is only populated if Init has been called.
	vMajor, vMinor, vPatch uint
)

var (
	initOnce sync.Once
	initErr  error
)

// GetVersion returns the OpenSSL version to use for testing.
func GetVersion() string {
	v := os.Getenv("GO_OPENSSL_VERSION_OVERRIDE")
	if v != "" {
		if runtime.GOOS == "linux" {
			return "libssl.so." + v
		}
		return v
	}
	// TODO: not sure how we want to handle dynamically resolving the openssl version.
	// Try to find a supported version of OpenSSL on the system.
	// This is useful for local testing, where the user may not
	// have GO_OPENSSL_VERSION_OVERRIDE set.
	versions := []string{"3", "1.1.1", "1.1", "11", "111", "1.0.2", "1.0.0", "10"}
	for _, v = range versions {
		if runtime.GOOS == "darwin" {
			v = "libssl." + v + ".dylib"
		} else {
			v = "libssl.so." + v
		}
		if ok, _ := CheckVersion(v); ok {
			return v
		}
	}
	return "libssl.so"
}

// CheckVersion checks if the OpenSSL version can be loaded
// and if the FIPS mode is enabled.
// This function can be called before Init.
func CheckVersion(version string) (exists, fips bool) {
	handle, _ := dlopen(version)
	if handle == nil {
		return false, false
	}
	defer dlclose(handle)
	fips = C.go_openssl_fips_enabled(handle) == 1
	return true, fips
}

// Init loads and initializes OpenSSL from the shared library at path.
// It must be called before any other OpenSSL call, except CheckVersion.
//
// Only the first call to Init is effective.
// Subsequent calls will return the same error result as the one from the first call.
//
// The file is passed to dlopen() verbatim to load the OpenSSL shared library.
// For example, `file=libcrypto.so.1.1.1k-fips` makes Init look for the shared
// library libcrypto.so.1.1.1k-fips.
func Init(file string) error {
	initOnce.Do(func() {
		vMajor, vMinor, vPatch, initErr = opensslInit(file)
	})
	return initErr
}

func utoa(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}

func errUnsupportedVersion() error {
	return errors.New("openssl: OpenSSL version: " + utoa(vMajor) + "." + utoa(vMinor) + "." + utoa(vPatch))
}

// checkMajorVersion panics if the current major version is not expected.
func checkMajorVersion(expected uint) {
	if vMajor != expected {
		panic("openssl: incorrect major version (" + strconv.Itoa(int(vMajor)) + "), expected " + strconv.Itoa(int(expected)))
	}
}

type fail string

func (e fail) Error() string { return "openssl: " + string(e) + " failed" }

// VersionText returns the version text of the OpenSSL currently loaded.
func VersionText() string {
	return C.GoString(C.go_openssl_OpenSSL_version(0))
}

var (
	providerNameFips    = C.CString("fips")
	providerNameDefault = C.CString("default")
)

// FIPS returns true if OpenSSL is running in FIPS mode, else returns false.
func FIPS() bool {
	switch vMajor {
	case 1:
		return C.go_openssl_FIPS_mode() == 1
	case 3:
		// If FIPS is not enabled via default properties, then we are sure FIPS is not used.
		if C.go_openssl_EVP_default_properties_is_fips_enabled(nil) == 0 {
			return false
		}
		// EVP_default_properties_is_fips_enabled can return true even if the FIPS provider isn't loaded,
		// it is only based on the default properties.
		// We can be sure that the FIPS provider is available if we can fetch an algorithm, e.g., SHA2-256,
		// explicitly setting `fips=yes`.
		return C.go_openssl_OSSL_PROVIDER_available(nil, providerNameFips) == 1
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
	case 1:
		if C.go_openssl_FIPS_mode_set(mode) != 1 {
			return newOpenSSLError("FIPS_mode_set")
		}
		return nil
	case 3:
		var provName *C.char
		if enabled {
			provName = providerNameFips
		} else {
			provName = providerNameDefault
		}
		// Check if there is any provider that matches props.
		if C.go_openssl_OSSL_PROVIDER_available(nil, provName) != 1 {
			// If not, fallback to provName provider.
			if C.go_openssl_OSSL_PROVIDER_load(nil, provName) == nil {
				return newOpenSSLError("OSSL_PROVIDER_try_load")
			}
			// Make sure we now have a provider available.
			if C.go_openssl_OSSL_PROVIDER_available(nil, provName) != 1 {
				return fail("SetFIPS(" + strconv.FormatBool(enabled) + ") not supported")
			}
		}
		if C.go_openssl_EVP_default_properties_enable_fips(nil, mode) != 1 {
			return newOpenSSLError("openssl: EVP_default_properties_enable_fips")
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

func newOpenSSLError(msg string) error {
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
			e = C.go_openssl_ERR_get_error_line(&file, &line)
		case 3:
			e = C.go_openssl_ERR_get_error_all(&file, &line, nil, nil, nil)
		default:
			panic(errUnsupportedVersion())
		}
		if e == 0 {
			break
		}
		b.WriteByte('\n')
		var buf [256]byte
		C.go_openssl_ERR_error_string_n(e, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
		b.WriteString(string(buf[:]) + "\n\t" + C.GoString(file) + ":" + strconv.Itoa(int(line)))
	}
	return errors.New(b.String())
}

var unknownFile = "<go code>\000"

// caller reports file and line number information about function invocations on
// the calling goroutine's stack, in a form suitable for passing to C code.
// The argument skip is the number of stack frames to ascend, with 0 identifying
// the caller of caller. The return values report the file name and line number
// within the file of the corresponding call. The returned file is a C string
// with static storage duration.
func caller(skip int) (file *C.char, line C.int) {
	_, f, l, ok := runtime.Caller(skip + 1)
	if !ok {
		f = unknownFile
	}
	// The underlying bytes of the file string are null-terminated rodata with
	// static lifetimes, so can be safely passed to C without worrying about
	// leaking memory or use-after-free.
	return (*C.char)(noescape(unsafe.Pointer(unsafe.StringData(f)))), C.int(l)
}

func CheckLeaks() {
	C.go_openssl_do_leak_check()
}

// versionAtOrAbove returns true when
// (vMajor, vMinor, vPatch) >= (major, minor, patch),
// compared lexicographically.
func versionAtOrAbove(major, minor, patch uint) bool {
	return vMajor > major || (vMajor == major && vMinor > minor) || (vMajor == major && vMinor == minor && vPatch >= patch)
}
