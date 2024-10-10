#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t

// #include <openssl/crypto.h>
enum {
    GO_OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L,
    GO_OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L,
    GO_OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L,
    GO_OPENSSL_INIT_LOAD_CONFIG = 0x00000040L
};

typedef void* GO_OPENSSL_INIT_SETTINGS_PTR;
typedef void* GO_OSSL_LIB_CTX_PTR;
typedef void* GO_OSSL_PROVIDER_PTR;

typedef void* GO_CRYPTO_THREADID_PTR;

// #include <openssl/ssl.h>
typedef void* GO_SSL_CTX_PTR;
typedef void* GO_SSL_METHOD_PTR;
typedef void* GO_SSL_PTR;

// FOR_ALL_LIBSSL_FUNCTIONS is the list of all functions from libcrypto that are used in this package.
// Forgetting to add a function here results in build failure with message reporting the function
// that needs to be added.
//
// The purpose of FOR_ALL_LIBSSL_FUNCTIONS is to define all libcrypto functions
// without depending on the openssl headers so it is easier to use this package
// with an openssl version different that the one used at build time.
//
// The following macros may not be defined at this point,
// they are not resolved here but just accumulated in FOR_ALL_LIBSSL_FUNCTIONS.
//
// DEFINEFUNC defines and loads openssl functions that can be directly called from Go as their signatures match
// the OpenSSL API and do not require special logic.
// The process will be aborted if the function can't be loaded.
//
// DEFINEFUNC_LEGACY_1_1 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.1.x. This indicates the function is required when using 1.1.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_LEGACY_1_0 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.0.x. This indicates the function is required when using 1.0.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_LEGACY_1 acts like DEFINEFUNC but only aborts the process if the function can't be loaded
// when using 1.x. This indicates the function is required when using 1.x, but is unused when using later versions.
// It also might not exist in later versions.
//
// DEFINEFUNC_1_1 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 1.1.0 or higher.
//
// DEFINEFUNC_1_1_1 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 1.1.1 or higher.
//
// DEFINEFUNC_3_0 acts like DEFINEFUNC but only aborts the process if function can't be loaded
// when using 3.0.0 or higher.
//
// DEFINEFUNC_RENAMED_1_1 acts like DEFINEFUNC but tries to load the function using the new name when using >= 1.1.x
// and the old name when using 1.0.2. In both cases the function will have the new name.
//
// DEFINEFUNC_RENAMED_3_0 acts like DEFINEFUNC but tries to load the function using the new name when using >= 3.x
// and the old name when using 1.x. In both cases the function will have the new name.
//
// #include <openssl/crypto.h>
// #include <openssl/err.h>
// #include <openssl/rsa.h>
// #include <openssl/hmac.h>
// #include <openssl/ec.h>
// #include <openssl/rand.h>
// #include <openssl/evp.h>
// #include <openssl/dsa.h>
// #if OPENSSL_VERSION_NUMBER >= 0x30000000L
// #include <openssl/provider.h>
// #include <openssl/param_build.h>
// #endif
// #if OPENSSL_VERSION_NUMBER < 0x10100000L
// #include <openssl/bn.h>
// #endif
#define FOR_ALL_LIBSSL_FUNCTIONS \
DEFINEFUNC(void, ERR_error_string_n, (unsigned long e, char *buf, size_t len), (e, buf, len)) \
DEFINEFUNC_LEGACY_1(unsigned long, ERR_get_error_line, (const char **file, int *line), (file, line)) \
DEFINEFUNC_3_0(unsigned long, ERR_get_error_all, (const char **file, int *line, const char **func, const char **data, int *flags), (file, line, func, data, flags)) \
DEFINEFUNC_RENAMED_1_1(const char *, OpenSSL_version, SSLeay_version, (int type), (type)) \
DEFINEFUNC_LEGACY_1_0(void, ERR_load_crypto_strings, (void), ()) \
DEFINEFUNC_LEGACY_1_0(void, ERR_remove_thread_state, (const GO_CRYPTO_THREADID_PTR tid), (tid)) \
DEFINEFUNC_LEGACY_1_0(int, CRYPTO_num_locks, (void), ()) \
DEFINEFUNC_LEGACY_1_0(int, CRYPTO_THREADID_set_callback, (void (*threadid_func) (GO_CRYPTO_THREADID_PTR)), (threadid_func)) \
DEFINEFUNC_LEGACY_1_0(void, CRYPTO_THREADID_set_numeric, (GO_CRYPTO_THREADID_PTR id, unsigned long val), (id, val)) \
DEFINEFUNC_LEGACY_1_0(void, CRYPTO_set_locking_callback, (void (*locking_function)(int mode, int n, const char *file, int line)), (locking_function)) \
DEFINEFUNC_LEGACY_1_0(void, OPENSSL_add_all_algorithms_conf, (void), ()) \
DEFINEFUNC_1_1(int, OPENSSL_init_ssl, (uint64_t ops, const GO_OPENSSL_INIT_SETTINGS_PTR settings), (ops, settings)) \
/* The SSL_library_init() and OpenSSL_add_ssl_algorithms() functions were */ \
/* deprecated in OpenSSL 1.1.0 by OPENSSL_init_ssl(). */ \
/* As of version 1.1.0 OpenSSL will automatically allocate all resources */ \
/* that it needs so no explicit initialisation is required. Similarly it */ \
/* will also automatically deinitialise as required. */ \
DEFINEFUNC_LEGACY_1_0(int, SSL_library_init, (void), ()) \
DEFINEFUNC_LEGACY_1(int, FIPS_mode, (void), ()) \
DEFINEFUNC_LEGACY_1(int, FIPS_mode_set, (int r), (r)) \
DEFINEFUNC_3_0(int, EVP_default_properties_is_fips_enabled, (GO_OSSL_LIB_CTX_PTR libctx), (libctx)) \
DEFINEFUNC_3_0(int, EVP_default_properties_enable_fips, (GO_OSSL_LIB_CTX_PTR libctx, int enable), (libctx, enable)) \
DEFINEFUNC_3_0(int, OSSL_PROVIDER_available, (GO_OSSL_LIB_CTX_PTR libctx, const char *name), (libctx, name)) \
DEFINEFUNC_3_0(GO_OSSL_PROVIDER_PTR, OSSL_PROVIDER_load, (GO_OSSL_LIB_CTX_PTR libctx, const char *name), (libctx, name)) \
/* Support for SSLv2 and the corresponding SSLv2_method(), SSLv2_server_method() */ \
/* and SSLv2_client_method() functions where removed in OpenSSL 1.1.0. */ \
/* SSLv23_method(), SSLv23_server_method() and SSLv23_client_method() were */ \
/* deprecated and the preferred TLS_method(), TLS_server_method() and */ \
/* TLS_client_method() functions were added in OpenSSL 1.1.0. */ \
/* SSLv23_method(), SSLv23_server_method(), SSLv23_client_method() */ \
/* are the general-purpose version-flexible SSL/TLS methods. */ \
/* The supported protocols are SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2. */ \
DEFINEFUNC_RENAMED_1_1(GO_SSL_METHOD_PTR, TLS_method, SSLv23_method, (void), ()) \
DEFINEFUNC_RENAMED_1_1(GO_SSL_METHOD_PTR, TLS_client_method, SSLv23_client_method, (void), ()) \
DEFINEFUNC_RENAMED_1_1(GO_SSL_METHOD_PTR, TLS_server_method, SSLv23_server_method, (void), ()) \
DEFINEFUNC(GO_SSL_CTX_PTR, SSL_CTX_new, (GO_SSL_METHOD_PTR method), (method)) \
DEFINEFUNC(void, SSL_CTX_free, (GO_SSL_CTX_PTR ctx), (ctx)) \
DEFINEFUNC(GO_SSL_PTR, SSL_new, (GO_SSL_CTX_PTR ctx), (ctx)) \
DEFINEFUNC(void, SSL_free, (GO_SSL_PTR ctx), (ctx)) \
DEFINEFUNC(void, SSL_clear, (GO_SSL_PTR ctx), (ctx)) \
DEFINEFUNC(int, SSL_set_fd, (GO_SSL_PTR ctx, int fd), (ctx, fd)) \
DEFINEFUNC(int, SSL_connect, (GO_SSL_PTR ctx), (ctx)) \
DEFINEFUNC(int, SSL_write, (GO_SSL_PTR ctx, const void *buf, int num), (ctx, buf, num)) \
DEFINEFUNC(int, SSL_read, (GO_SSL_PTR ctx, void *buf, int num), (ctx, buf, num)) \

// Define pointers to all the used OpenSSL functions.
// Calling C function pointers from Go is currently not supported.
// It is possible to circumvent this by using a C function wrapper.
// https://pkg.go.dev/cmd/cgo
#define DEFINEFUNC(ret, func, args, argscall)      \
    extern ret (*_g_##func)args;                   \
    static inline ret go_openssl_##func args       \
    {                                              \
        return _g_##func argscall;                 \
    }
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall)    \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall)    \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall)  \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall)   \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1_1(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall)     \
    DEFINEFUNC(ret, func, args, argscall)

FOR_ALL_LIBSSL_FUNCTIONS

#undef DEFINEFUNC
#undef DEFINEFUNC_LEGACY_1_1
#undef DEFINEFUNC_LEGACY_1_0
#undef DEFINEFUNC_LEGACY_1
#undef DEFINEFUNC_1_1
#undef DEFINEFUNC_1_1_1
#undef DEFINEFUNC_3_0
#undef DEFINEFUNC_RENAMED_1_1
#undef DEFINEFUNC_RENAMED_3_0
