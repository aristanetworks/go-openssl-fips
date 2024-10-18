#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t

// OpenSSL initialization options
enum {
    GO_OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L,
    GO_OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L,
    GO_OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L,
    GO_OPENSSL_INIT_LOAD_CONFIG = 0x00000040L
};

// SSL/TLS options
enum {
    GO_SSL_OP_NO_SSLv2 = 0x01000000L,
    GO_SSL_OP_NO_SSLv3 = 0x02000000L,
    GO_SSL_OP_NO_TLSv1 = 0x04000000L,
    GO_SSL_OP_NO_TLSv1_1 = 0x10000000L,
    GO_SSL_OP_NO_TLSv1_2 = 0x08000000L,
    GO_SSL_OP_NO_TLSv1_3 = 0x20000000L,
    GO_SSL_OP_ALL = 0x80000BFFL,
    GO_SSL_OP_NO_TICKET = 0x00004000L,
    GO_SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000L,
    GO_SSL_OP_NO_COMPRESSION = 0x00020000L,
    GO_SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000L,
    GO_SSL_OP_TLS_ROLLBACK_BUG = 0x00000400L
};

// SSL verify modes
/*
 * use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 3 options are
 * 'ored' with SSL_VERIFY_PEER if they are desired
 */
enum {
    GO_SSL_VERIFY_NONE = 0x00,
    GO_SSL_VERIFY_PEER = 0x01,
    GO_SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02,
    GO_SSL_VERIFY_CLIENT_ONCE = 0x04,
    GO_SSL_VERIFY_POST_HANDSHAKE = 0x08
};

// SSL_CTX_set_mode options
enum {
    GO_SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001L,
    GO_SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002L,
    GO_SSL_MODE_AUTO_RETRY = 0x00000004L,
    GO_SSL_MODE_RELEASE_BUFFERS = 0x00000010L
};

// TLS version constants
enum {
    GO_TLS1_VERSION = 0x0301,
    GO_TLS1_1_VERSION = 0x0302,
    GO_TLS1_2_VERSION = 0x0303,
    GO_TLS1_3_VERSION = 0x0304
};

// Error constants
enum {
    GO_SSL_ERROR_NONE = 0,
    GO_SSL_ERROR_SSL = 1,
    GO_SSL_ERROR_WANT_READ = 2,
    GO_SSL_ERROR_WANT_WRITE = 3,
    GO_SSL_ERROR_WANT_X509_LOOKUP = 4,
    GO_SSL_ERROR_SYSCALL = 5,
    GO_SSL_ERROR_ZERO_RETURN = 6,
    GO_SSL_ERROR_WANT_CONNECT = 7,
    GO_SSL_ERROR_WANT_ACCEPT = 8
};

typedef void *GO_X509_VERIFY_PARAM_PTR;

// X509 verification flags
enum {
    GO_X509_V_FLAG_USE_CHECK_TIME = 0x2,
    GO_X509_V_FLAG_CRL_CHECK = 0x4,
    GO_X509_V_FLAG_CRL_CHECK_ALL = 0x8,
    GO_X509_V_FLAG_IGNORE_CRITICAL = 0x10,
    GO_X509_V_FLAG_X509_STRICT = 0x20,
    GO_X509_V_FLAG_ALLOW_PROXY_CERTS = 0x40,
    GO_X509_V_FLAG_POLICY_CHECK = 0x80,
    GO_X509_V_FLAG_EXPLICIT_POLICY = 0x100,
    GO_X509_V_FLAG_INHIBIT_ANY = 0x200,
    GO_X509_V_FLAG_INHIBIT_MAP = 0x400,
    GO_X509_V_FLAG_NOTIFY_POLICY = 0x800,
    GO_X509_V_FLAG_EXTENDED_CRL_SUPPORT = 0x1000,
    GO_X509_V_FLAG_USE_DELTAS = 0x2000,
    GO_X509_V_FLAG_CHECK_SS_SIGNATURE = 0x4000,
    GO_X509_V_FLAG_TRUSTED_FIRST = 0x8000,
    GO_X509_V_FLAG_SUITEB_128_LOS_ONLY = 0x10000,
    GO_X509_V_FLAG_SUITEB_192_LOS = 0x20000,
    GO_X509_V_FLAG_SUITEB_128_LOS = 0x30000,
    GO_X509_V_FLAG_PARTIAL_CHAIN = 0x80000,
    GO_X509_V_FLAG_NO_ALT_CHAINS = 0x100000,
    GO_X509_V_FLAG_NO_CHECK_TIME = 0x200000
};

// X509 verification return values
enum {
    GO_X509_V_OK                                       = 0,
    GO_X509_V_ERR_UNSPECIFIED                          = 1,
    GO_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            = 2,
    GO_X509_V_ERR_UNABLE_TO_GET_CRL                    = 3,
    GO_X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     = 4,
    GO_X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      = 5,
    GO_X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   = 6,
    GO_X509_V_ERR_CERT_SIGNATURE_FAILURE               = 7,
    GO_X509_V_ERR_CRL_SIGNATURE_FAILURE                = 8,
    GO_X509_V_ERR_CERT_NOT_YET_VALID                   = 9,
    GO_X509_V_ERR_CERT_HAS_EXPIRED                     = 10,
    GO_X509_V_ERR_CRL_NOT_YET_VALID                    = 11,
    GO_X509_V_ERR_CRL_HAS_EXPIRED                      = 12,
    GO_X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       = 13,
    GO_X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        = 14,
    GO_X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       = 15,
    GO_X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       = 16,
    GO_X509_V_ERR_OUT_OF_MEM                           = 17,
    GO_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          = 18,
    GO_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            = 19,
    GO_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    = 20,
    GO_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      = 21,
    GO_X509_V_ERR_CERT_CHAIN_TOO_LONG                  = 22,
    GO_X509_V_ERR_CERT_REVOKED                         = 23,
    GO_X509_V_ERR_NO_ISSUER_PUBLIC_KEY                 = 24,
    GO_X509_V_ERR_PATH_LENGTH_EXCEEDED                 = 25,
    GO_X509_V_ERR_INVALID_PURPOSE                      = 26,
    GO_X509_V_ERR_CERT_UNTRUSTED                       = 27,
    GO_X509_V_ERR_CERT_REJECTED                        = 28
};


// SSL and SSL_CTX ctrl constants
enum {
    GO_SSL_CTRL_OPTIONS = 32,
    GO_SSL_CTRL_SET_TLSEXT_HOSTNAME = 55,
    GO_SSL_CTRL_SET_MIN_PROTO_VERSION = 123,
    GO_SSL_CTRL_SET_MAX_PROTO_VERSION = 124
};

enum {
    GO_TLSEXT_NAMETYPE_host_name = 0,
};


typedef void* GO_OPENSSL_INIT_SETTINGS_PTR;
typedef void* GO_OSSL_LIB_CTX_PTR;
typedef void* GO_OSSL_PROVIDER_PTR;
typedef void* GO_SSL_verify_cb_PTR;
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
DEFINEFUNC_1_1(int, SSL_write_ex, (GO_SSL_PTR s, const void *buf, size_t num, size_t *written), (s, buf, num, written)) \
DEFINEFUNC_1_1(int, SSL_read_ex, (GO_SSL_PTR s, void *buf, size_t num, size_t *readbytes), (s, buf, num, readbytes)) \
/* SSL_CTX_ctrl is needed for SSL_CTX_set_min_proto_version */ \
DEFINEFUNC(long, SSL_CTX_ctrl, (GO_SSL_CTX_PTR ctx, int cmd, long larg, void *parg), (ctx, cmd, larg, parg)) \
DEFINEFUNC(void, SSL_CTX_set_verify, (GO_SSL_CTX_PTR ctx, int mode, GO_SSL_verify_cb_PTR vb), (ctx, mode, vb)) \
DEFINEFUNC(int, SSL_CTX_set_default_verify_paths, (GO_SSL_CTX_PTR ctx), (ctx)) \
/* SSL_ctrl is needed for SSL_set_tlsext_host_name */ \
DEFINEFUNC(long, SSL_ctrl, (GO_SSL_PTR ctx, int cmd, long larg, void *parg), (ctx, cmd, larg, parg)) \
DEFINEFUNC_1_1(int, SSL_set1_host, (GO_SSL_PTR s, const char *hostname), (s, hostname)) \
DEFINEFUNC(long, SSL_get_verify_result, (const GO_SSL_PTR ssl), (ssl)) \
DEFINEFUNC(GO_X509_VERIFY_PARAM_PTR, SSL_get0_param, (GO_SSL_PTR s), (s)) \
DEFINEFUNC_1_1(uint64_t, SSL_CTX_set_options, (GO_SSL_CTX_PTR ctx, uint64_t op), (ctx, op)) \
/* Used in OpenSSL <= 1.0.x */ \
DEFINEFUNC(int, SSL_set1_param, (GO_SSL_PTR ssl, GO_X509_VERIFY_PARAM_PTR vpm), (ssl, vpm)) \
DEFINEFUNC(GO_X509_VERIFY_PARAM_PTR, X509_VERIFY_PARAM_new, (void), ()) \
DEFINEFUNC(void, X509_VERIFY_PARAM_free, (GO_X509_VERIFY_PARAM_PTR vpm), (vpm)) \
DEFINEFUNC(int, X509_VERIFY_PARAM_set_flags, (GO_X509_VERIFY_PARAM_PTR vpm, long flags), (vpm, flags)) \
DEFINEFUNC(int, X509_VERIFY_PARAM_set1_host, (GO_X509_VERIFY_PARAM_PTR vpm, const char *name, size_t namelen), (vpm, name, namelen)) \
DEFINEFUNC(const char*, X509_verify_cert_error_string, (long n), (n)) \
DEFINEFUNC(int, SSL_get_error, (GO_SSL_PTR ssl, int ret), (ssl, ret)) \
DEFINEFUNC(int, SSL_shutdown, (GO_SSL_PTR ssl), (ssl)) \

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
