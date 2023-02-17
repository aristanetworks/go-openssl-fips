//go:build linux && !android
// +build linux,!android

package openssl

// #include "goopenssl.h"
import "C"
import (
	"hash"
	"runtime"
	"unsafe"
)

// NewHMAC returns a new HMAC using OpenSSL.
// The function h must return a hash implemented by
// OpenSSL (for example, h could be openssl.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	ch := h()
	md := hashToMD(ch)
	if md == nil {
		return nil
	}

	if len(key) == 0 {
		// This is supported in OpenSSL/Standard lib and as such
		// we must support it here. When using HMAC with a null key
		// HMAC_Init will try and reuse the key from the ctx. This is
		// not the behavior previously implemented, so as a workaround
		// we pass an "empty" key.
		key = make([]byte, C.GO_EVP_MAX_MD_SIZE)
	}

	switch vMajor {
	case 1:
		return newHMAC1(key, ch, md)
	case 3:
		return newHMAC3(key, ch, md)
	default:
		panic(errUnsupportedVersion())
	}
}

// hmacCtx3 is used for OpenSSL 1.
type hmacCtx1 struct {
	ctx C.GO_HMAC_CTX_PTR
}

// hmacCtx3 is used for OpenSSL 3.
type hmacCtx3 struct {
	ctx C.GO_EVP_MAC_CTX_PTR
	key []byte
}

type opensslHMAC struct {
	ctx1      hmacCtx1
	ctx3      hmacCtx3
	size      int
	blockSize int
	sum       []byte
}

func newHMAC1(key []byte, h hash.Hash, md C.GO_EVP_MD_PTR) *opensslHMAC {
	ctx := hmacCtxNew()
	if ctx == nil {
		panic("openssl: EVP_MAC_CTX_new failed")
	}
	if C.go_openssl_HMAC_Init_ex(ctx, unsafe.Pointer(&key[0]), C.int(len(key)), md, nil) == 0 {
		panic(newOpenSSLError("HMAC_Init_ex failed"))
	}
	hmac := &opensslHMAC{
		size:      h.Size(),
		blockSize: h.BlockSize(),
		ctx1:      hmacCtx1{ctx},
	}
	runtime.SetFinalizer(hmac, (*opensslHMAC).finalize)
	return hmac
}

func newHMAC3(key []byte, h hash.Hash, md C.GO_EVP_MD_PTR) *opensslHMAC {
	mac := C.go_openssl_EVP_MAC_fetch(nil, paramAlgHMAC, nil)
	ctx := C.go_openssl_EVP_MAC_CTX_new(mac)
	if ctx == nil {
		panic("openssl: EVP_MAC_CTX_new failed")
	}
	digest := C.go_openssl_EVP_MD_get0_name(md)
	params := newParamsBuilder()
	params.addUTF8(paramDigest, C.GoString(digest))
	if C.go_openssl_EVP_MAC_init(ctx, base(key), C.size_t(len(key)), &params.params[0]) == 0 {
		panic(newOpenSSLError("EVP_MAC_init failed"))
	}
	hkey := make([]byte, len(key))
	copy(hkey, key)
	hmac := &opensslHMAC{
		size:      h.Size(),
		blockSize: h.BlockSize(),
		ctx3:      hmacCtx3{ctx, hkey},
	}
	runtime.SetFinalizer(hmac, (*opensslHMAC).finalize)
	return hmac
}

func (h *opensslHMAC) Reset() {
	switch vMajor {
	case 1:
		if C.go_openssl_HMAC_Init_ex(h.ctx1.ctx, nil, 0, nil, nil) == 0 {
			panic(newOpenSSLError("HMAC_Init_ex failed"))
		}
	case 3:
		// EVP_MAC_init only reset the ctx internal state if a key is passed
		// when using OpenSSL 3.0.1 and 3.0.2.
		// See https://github.com/openssl/openssl/issues/17811.
		if C.go_openssl_EVP_MAC_init(h.ctx3.ctx, base(h.ctx3.key), C.size_t(len(h.ctx3.key)), nil) == 0 {
			panic(newOpenSSLError("EVP_MAC_init failed"))
		}
	default:
		panic(errUnsupportedVersion())
	}

	runtime.KeepAlive(h) // Next line will keep h alive too; just making doubly sure.
	h.sum = nil
}

func (h *opensslHMAC) finalize() {
	switch vMajor {
	case 1:
		hmacCtxFree(h.ctx1.ctx)
	case 3:
		C.go_openssl_EVP_MAC_CTX_free(h.ctx3.ctx)
	default:
		panic(errUnsupportedVersion())
	}
}

func (h *opensslHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		switch vMajor {
		case 1:
			C.go_openssl_HMAC_Update(h.ctx1.ctx, base(p), C.size_t(len(p)))
		case 3:
			C.go_openssl_EVP_MAC_update(h.ctx3.ctx, base(p), C.size_t(len(p)))
		default:
			panic(errUnsupportedVersion())
		}
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *opensslHMAC) Size() int {
	return h.size
}

func (h *opensslHMAC) BlockSize() int {
	return h.blockSize
}

func (h *opensslHMAC) Sum(in []byte) []byte {
	if h.sum == nil {
		size := h.Size()
		h.sum = make([]byte, size)
	}
	// Make copy of context because Go hash.Hash mandates
	// that Sum has no effect on the underlying stream.
	// In particular it is OK to Sum, then Write more, then Sum again,
	// and the second Sum acts as if the first didn't happen.
	switch vMajor {
	case 1:
		ctx2 := hmacCtxNew()
		if ctx2 == nil {
			panic("openssl: HMAC_CTX_new failed")
		}
		defer hmacCtxFree(ctx2)
		if C.go_openssl_HMAC_CTX_copy(ctx2, h.ctx1.ctx) == 0 {
			panic("openssl: HMAC_CTX_copy failed")
		}
		C.go_openssl_HMAC_Final(ctx2, base(h.sum), nil)
	case 3:
		ctx2 := C.go_openssl_EVP_MAC_CTX_dup(h.ctx3.ctx)
		if ctx2 == nil {
			panic("openssl: EVP_MAC_CTX_dup failed")
		}
		defer C.go_openssl_EVP_MAC_CTX_free(ctx2)
		C.go_openssl_EVP_MAC_final(ctx2, base(h.sum), nil, C.size_t(len(h.sum)))
	default:
		panic(errUnsupportedVersion())
	}
	return append(in, h.sum...)
}

func hmacCtxNew() C.GO_HMAC_CTX_PTR {
	if vMajor == 1 && vMinor == 0 {
		// 0x120 is the sizeof value when building against OpenSSL 1.0.2 on Ubuntu 16.04.
		ctx := (C.GO_HMAC_CTX_PTR)(C.malloc(0x120))
		if ctx != nil {
			C.go_openssl_HMAC_CTX_init(ctx)
		}
		return ctx
	}
	return C.go_openssl_HMAC_CTX_new()
}

func hmacCtxFree(ctx C.GO_HMAC_CTX_PTR) {
	if vMajor == 1 && vMinor == 0 {
		C.go_openssl_HMAC_CTX_cleanup(ctx)
		C.free(unsafe.Pointer(ctx))
		return
	}
	C.go_openssl_HMAC_CTX_free(ctx)
}