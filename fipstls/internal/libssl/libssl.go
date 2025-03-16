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
	initOnce *sync.Once = new(sync.Once)
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
		if file == "" {
			file = GetVersion()
		}
		vMajor, vMinor, vPatch, initErr = opensslInit(file)
	})
	return initErr
}

// Reset resets initOnce. Used for testing only.
func Reset() {
	initOnce = new(sync.Once)
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

// FIPS returns true if OpenSSL is running in FIPS mode and there is
// a provider available that supports FIPS. It returns false otherwise.
func FIPS() bool {
	switch vMajor {
	case 1:
		return C.go_openssl_FIPS_mode() == 1
	case 3:
		// Check if the default properties contain `fips=1`.
		if C.go_openssl_EVP_default_properties_is_fips_enabled(nil) != 1 {
			// Note that it is still possible that the provider used by default is FIPS-compliant,
			// so check if the MD5 algorithm is unavailable & SHA-256 is available for the case
			// where the default provider is FIPS-compliant.
			return proveNoMd5("") && proveSHA256("")
		}
		// Check if the SHA-256 algorithm is available. If it is, then we can be sure that there is a provider available that matches
		// the `fips=1` query. Most notably, this works for the common case of using the built-in FIPS provider.
		//
		// Note that this approach has a small chance of false negative if the FIPS provider doesn't provide the SHA-256 algorithm,
		// but that is highly unlikely because SHA-256 is one of the most common algorithms and fundamental to many cryptographic operations.
		// It also has a small chance of false positive if the FIPS provider implements the SHA-256 algorithm but not the other algorithms
		// used by the caller application, but that is also unlikely because the FIPS provider should provide all common algorithms.
		return proveSHA256("")
	default:
		panic(errUnsupportedVersion())
	}
}

// CheckFIPS will try to fetch the MD5 digest algorithm with the currently loaded provider. It will
// return an error if MD5 implementation cannot be fetched, and is expected to return an error if
// the FIPS provider is loaded.
func CheckFIPS() error {
	prov, err := md5Provider("")
	if err != nil {
		return err
	}
	if prov == nil {
		return errors.New("libssl: failed to get MD5 provider")
	}
	return nil
}

// FIPSCapable returns true if the provider used by default matches the `fips=yes` query.
// It is useful for checking whether OpenSSL is capable of running in FIPS mode regardless
// of whether FIPS mode is explicitly enabled. For example, Azure Linux 3 doesn't set the
// `fips=yes` query in the default properties, but sets the default provider to be SCOSSL,
// which is FIPS-capable.
//
// Considerations:
//   - Multiple calls to FIPSCapable can return different values if [SetFIPS] is called in between.
//   - Can return true even if [FIPS] returns false, because [FIPS] also checks whether
//     the default properties contain `fips=yes`.
//   - When using OpenSSL 3, will always return true if [FIPS] returns true.
//   - When using OpenSSL 1, Will always return the same value as [FIPS].
//   - OpenSSL 3 doesn't provide a way to know if a provider is FIPS-capable. This function uses
//     some heuristics that should be treated as an implementation detail that may change in the future.
func FIPSCapable() bool {
	if FIPS() {
		return true
	}
	if vMajor == 3 {
		// Load the provider with and without the `fips=yes` query.
		// If the providers are the same, then the default provider is FIPS-capable.
		provFIPS := sha256Provider(_ProviderNameFips)
		if provFIPS != nil {
			return true
		}
		provDefault := sha256Provider("")
		return provFIPS == provDefault
	}
	return false
}

// SetFIPS enables or disables FIPS mode.
//
// For OpenSSL 3, if there is no provider available that supports FIPS mode,
// SetFIPS will try to load a built-in provider that supports FIPS mode.
func SetFIPS(enable bool) error {
	if FIPS() == enable {
		// Already in the desired state.
		return nil
	}
	var mode C.int
	if enable {
		mode = C.int(int32(1))
	} else {
		mode = C.int(int32(0))
	}
	switch vMajor {
	case 1:
		if C.go_openssl_FIPS_mode_set(mode) == 0 {
			return errors.New("libssl: failed to enable FIPS mode")
		}
		return nil
	case 3:
		var shaProps, provName cString
		if enable {
			shaProps = _PropFIPSYes
			provName = _ProviderNameFips
		} else {
			shaProps = _PropFIPSNo
			provName = _ProviderNameDefault
		}
		if !proveSHA256(shaProps) {
			// There is no provider available that supports the desired FIPS mode.
			// Try to load the built-in provider associated with the given mode.
			if p, _ := C.go_openssl_OSSL_PROVIDER_try_load(nil,
				(*C.char)(unsafe.Pointer(provName.ptr())), 1); p == nil {
				// The built-in provider was not loaded successfully, we can't enable FIPS mode.
				C.go_openssl_ERR_clear_error()
				return errors.New("libssl: FIPS mode not supported by any provider")
			}
		}
		_, err := C.go_openssl_EVP_default_properties_enable_fips(nil, mode)
		return err
	default:
		panic(errUnsupportedVersion())
	}
}

const BUF_SIZE = 1024

func GetFipsProviderInfo() (string, error) {
	if vMajor != 3 {
		return "", errors.New("libssl: unsupported on OpenSSL < 3.x")
	}
	var buf [BUF_SIZE]C.char
	if C.go_openssl_get_fips_provider_info((*C.char)(unsafe.Pointer(&buf)), BUF_SIZE) != 0 {
		return "", errors.New("libssl: failed to get FIPS provider info")
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf))), nil
}

// sha256Provider returns the provider for the SHA-256 algorithm
// using the given properties.
func sha256Provider(props cString) C.GO_OSSL_PROVIDER_PTR {
	md, _ := C.go_openssl_EVP_MD_fetch(nil,
		(*C.char)(unsafe.Pointer(_DigestNameSHA2_256.ptr())),
		(*C.char)(unsafe.Pointer(props.ptr())))
	if md == nil {
		C.go_openssl_ERR_clear_error()
		return nil
	}
	defer C.go_openssl_EVP_MD_free(md)
	return C.go_openssl_EVP_MD_get0_provider(md)
}

// proveSHA256 checks if the SHA-256 algorithm is available
// using the given properties.
func proveSHA256(props cString) bool {
	return sha256Provider(props) != nil
}

// md5Provider returns the provider for the MD5 algorithm
// using the given properties.
func md5Provider(props cString) (C.GO_OSSL_PROVIDER_PTR, error) {
	md, _ := C.go_openssl_EVP_MD_fetch(nil,
		(*C.char)(unsafe.Pointer(_DigestNameMD5.ptr())),
		(*C.char)(unsafe.Pointer(props.ptr())))
	if md == nil {
		return nil, NewOpenSSLError("libssl: failed to get MD5 message digest")
	}
	defer C.go_openssl_EVP_MD_free(md)
	return C.go_openssl_EVP_MD_get0_provider(md), nil
}

// proveNoMd5 checks if the MD5 algorithm is unavailable
// using the given properties.
func proveNoMd5(props cString) bool {
	prov, err := md5Provider(props)
	if err != nil {
		return true
	}
	return prov == nil
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
