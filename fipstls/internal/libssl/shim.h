#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t
#include "flags.h"

typedef void *GO_OPENSSL_INIT_SETTINGS_PTR;
typedef void *GO_OSSL_LIB_CTX_PTR;
typedef void *GO_OSSL_PROVIDER_PTR;
typedef void *GO_SSL_verify_cb_PTR;
typedef void *GO_CRYPTO_THREADID_PTR;
typedef void *GO_X509_VERIFY_PARAM_PTR;

// #include <openssl/ssl.h>
typedef void *GO_SSL_CTX_PTR;
typedef void *GO_SSL_METHOD_PTR;
typedef void *GO_SSL_PTR;
typedef void *GO_SSL_SESSION_PTR;
typedef void *GO_BIO_ADDRINFO_PTR;
typedef void *GO_BIO_ADDR_PTR;
typedef void *GO_BIO_PTR;
typedef void *GO_BIO_METHOD_PTR;

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
#define FOR_ALL_LIBSSL_FUNCTIONS                                                                                                                                                                                                                            \
    DEFINEFUNC(void, ERR_error_string_n, (unsigned long e, char *buf, size_t len), (e, buf, len))                                                                                                                                                           \
    DEFINEFUNC_LEGACY_1(unsigned long, ERR_get_error_line, (const char **file, int *line), (file, line))                                                                                                                                                    \
    DEFINEFUNC_3_0(unsigned long, ERR_get_error_all, (const char **file, int *line, const char **func, const char **data, int *flags), (file, line, func, data, flags))                                                                                     \
    DEFINEFUNC_RENAMED_1_1(const char *, OpenSSL_version, SSLeay_version, (int type), (type))                                                                                                                                                               \
    DEFINEFUNC_1_1(int, OPENSSL_init_ssl, (uint64_t ops, const GO_OPENSSL_INIT_SETTINGS_PTR settings), (ops, settings))                                                                                                                                     \
    DEFINEFUNC_LEGACY_1_0(int, SSL_library_init, (void), ())                                                                                                                                                                                                \
    DEFINEFUNC_LEGACY_1(int, FIPS_mode, (void), ())                                                                                                                                                                                                         \
    DEFINEFUNC_LEGACY_1(int, FIPS_mode_set, (int r), (r))                                                                                                                                                                                                   \
    DEFINEFUNC_3_0(int, EVP_default_properties_is_fips_enabled, (GO_OSSL_LIB_CTX_PTR libctx), (libctx))                                                                                                                                                     \
    DEFINEFUNC_3_0(int, EVP_default_properties_enable_fips, (GO_OSSL_LIB_CTX_PTR libctx, int enable), (libctx, enable))                                                                                                                                     \
    DEFINEFUNC_3_0(int, OSSL_PROVIDER_available, (GO_OSSL_LIB_CTX_PTR libctx, const char *name), (libctx, name))                                                                                                                                            \
    DEFINEFUNC_3_0(GO_OSSL_PROVIDER_PTR, OSSL_PROVIDER_load, (GO_OSSL_LIB_CTX_PTR libctx, const char *name), (libctx, name))                                                                                                                                \
    /* Support for SSLv2 and the corresponding SSLv2_method(), SSLv2_server_method() */                                                                                                                                                                     \
    /* and SSLv2_client_method() functions where removed in OpenSSL 1.1.0. */                                                                                                                                                                               \
    /* SSLv23_method(), SSLv23_server_method() and SSLv23_client_method() were */                                                                                                                                                                           \
    /* deprecated and the preferred TLS_method(), TLS_server_method() and */                                                                                                                                                                                \
    /* TLS_client_method() functions were added in OpenSSL 1.1.0. */                                                                                                                                                                                        \
    /* SSLv23_method(), SSLv23_server_method(), SSLv23_client_method() */                                                                                                                                                                                   \
    /* are the general-purpose version-flexible SSL/TLS methods. */                                                                                                                                                                                         \
    /* The supported protocols are SSLv2, SSLv3, TLSv1, TLSv1.1 and TLSv1.2. */                                                                                                                                                                             \
    DEFINEFUNC_RENAMED_1_1(GO_SSL_METHOD_PTR, TLS_method, SSLv23_method, (void), ())                                                                                                                                                                        \
    DEFINEFUNC_RENAMED_1_1(GO_SSL_METHOD_PTR, TLS_client_method, SSLv23_client_method, (void), ())                                                                                                                                                          \
    DEFINEFUNC_RENAMED_1_1(GO_SSL_METHOD_PTR, TLS_server_method, SSLv23_server_method, (void), ())                                                                                                                                                          \
    DEFINEFUNC(GO_SSL_CTX_PTR, SSL_CTX_new, (GO_SSL_METHOD_PTR method), (method))                                                                                                                                                                           \
    DEFINEFUNC(void, SSL_CTX_free, (GO_SSL_CTX_PTR ctx), (ctx))                                                                                                                                                                                             \
    DEFINEFUNC(GO_SSL_PTR, SSL_new, (GO_SSL_CTX_PTR ctx), (ctx))                                                                                                                                                                                            \
    DEFINEFUNC(void, SSL_free, (GO_SSL_PTR ctx), (ctx))                                                                                                                                                                                                     \
    DEFINEFUNC(void, SSL_clear, (GO_SSL_PTR ctx), (ctx))                                                                                                                                                                                                    \
    DEFINEFUNC(int, SSL_connect, (GO_SSL_PTR ssl), (ssl))                                                                                                                                                                                                   \
    DEFINEFUNC_1_1(int, SSL_write_ex, (GO_SSL_PTR s, const void *buf, size_t num, size_t *written), (s, buf, num, written))                                                                                                                                 \
    DEFINEFUNC_1_1(int, SSL_read_ex, (GO_SSL_PTR s, void *buf, size_t num, size_t *readbytes), (s, buf, num, readbytes)) /* SSL_CTX_ctrl is needed for SSL_CTX_set_min_proto_version */                                                                     \
    DEFINEFUNC(long, SSL_CTX_ctrl, (GO_SSL_CTX_PTR ctx, int cmd, long larg, void *parg), (ctx, cmd, larg, parg))                                                                                                                                            \
    DEFINEFUNC(int, SSL_CTX_set_alpn_protos, (GO_SSL_CTX_PTR ctx, const unsigned char *protos, unsigned protos_len), (ctx, protos, protos_len))                                                                                                             \
    DEFINEFUNC(int, SSL_select_next_proto, (unsigned char **out, unsigned char *outlen, const unsigned char *server, unsigned int server_len, const unsigned char *client, unsigned int client_len), (out, outlen, server, server_len, client, client_len)) \
    DEFINEFUNC(void, SSL_get0_alpn_selected, (const GO_SSL_PTR ssl, const unsigned char **data, unsigned int *len), (ssl, data, len))                                                                                                                       \
    DEFINEFUNC(void, SSL_CTX_set_verify, (GO_SSL_CTX_PTR ctx, int mode, GO_SSL_verify_cb_PTR vb), (ctx, mode, vb))                                                                                                                                          \
    DEFINEFUNC(int, SSL_CTX_set_default_verify_paths, (GO_SSL_CTX_PTR ctx), (ctx))                                                                                                                                                                          \
    DEFINEFUNC(int, SSL_CTX_load_verify_locations, (GO_SSL_CTX_PTR ctx, const char *CAfile, const char *CApath), (ctx, CAfile, CApath)) /* SSL_ctrl is needed for SSL_set_tlsext_host_name */                                                               \
    DEFINEFUNC(int, SSL_CTX_use_certificate_file, (GO_SSL_CTX_PTR ctx, const char *file, int type), (ctx, file, type))                                                                                                                                      \
    DEFINEFUNC(int, SSL_CTX_use_certificate_chain_file, (GO_SSL_CTX_PTR ctx, const char *file), (ctx, file))                                                                                                                                                \
    DEFINEFUNC(int, SSL_CTX_use_PrivateKey_file, (GO_SSL_CTX_PTR ctx, const char *file, int type), (ctx, file, type))                                                                                                                                       \
    DEFINEFUNC(int, SSL_CTX_check_private_key, (const GO_SSL_CTX_PTR ctx), (ctx))                                                                                                                                                                           \
    DEFINEFUNC(long, SSL_ctrl, (GO_SSL_PTR ctx, int cmd, long larg, void *parg), (ctx, cmd, larg, parg))                                                                                                                                                    \
    DEFINEFUNC_1_1(int, SSL_set1_host, (GO_SSL_PTR s, const char *hostname), (s, hostname))                                                                                                                                                                 \
    DEFINEFUNC(long, SSL_get_verify_result, (const GO_SSL_PTR ssl), (ssl))                                                                                                                                                                                  \
    DEFINEFUNC_1_1(uint64_t, SSL_CTX_set_options, (GO_SSL_CTX_PTR ctx, uint64_t op), (ctx, op))                                                                                                                                                             \
    DEFINEFUNC(const char *, X509_verify_cert_error_string, (long n), (n))                                                                                                                                                                                  \
    DEFINEFUNC(int, SSL_get_error, (GO_SSL_PTR ssl, int ret), (ssl, ret))                                                                                                                                                                                   \
    DEFINEFUNC(void, ERR_clear_error, (void), ())                                                                                                                                                                                                           \
    DEFINEFUNC(int, SSL_shutdown, (GO_SSL_PTR ssl), (ssl))                                                                                                                                                                                                  \
    DEFINEFUNC(int, SSL_get_shutdown, (GO_SSL_PTR ssl), (ssl))                                                                                                                                                                                              \
    DEFINEFUNC(void, SSL_set_shutdown, (GO_SSL_PTR ssl, int mode), (ssl, mode))                                                                                                                                                                             \
    DEFINEFUNC(void, SSL_set_connect_state, (GO_SSL_PTR ssl), (ssl))                                                                                                                                                                                        \
    DEFINEFUNC(int, SSL_do_handshake, (GO_SSL_PTR ssl), (ssl))                                                                                                                                                                                              \
    DEFINEFUNC(int, SSL_set_session, (GO_SSL_PTR ssl, GO_SSL_SESSION_PTR session), (ssl, session))                                                                                                                                                          \
    DEFINEFUNC(void, SSL_set_bio, (GO_SSL_PTR s, GO_BIO_PTR rbio, GO_BIO_PTR wbio), (s, rbio, wbio))                                                                                                                                                        \
    DEFINEFUNC_1_1(int, BIO_lookup_ex, (const char *host, const char *service, int lookup_type, int family, int socktype, int protocol, GO_BIO_ADDRINFO_PTR res), (host, service, lookup_type, family, socktype, protocol, res))                            \
    DEFINEFUNC_1_1(GO_BIO_ADDRINFO_PTR, BIO_ADDRINFO_next, (const GO_BIO_ADDRINFO_PTR ai), (ai))                                                                                                                                                            \
    DEFINEFUNC_1_1(int, BIO_socket, (int family, int socktype, int protocol, int options), (family, socktype, protocol, options))                                                                                                                           \
    DEFINEFUNC_1_1(int, BIO_ADDRINFO_family, (const GO_BIO_ADDRINFO_PTR ai), (ai))                                                                                                                                                                          \
    DEFINEFUNC_1_1(int, BIO_connect, (int sock, const GO_BIO_ADDR_PTR addr, int options), (sock, addr, options))                                                                                                                                            \
    DEFINEFUNC_1_1(GO_BIO_ADDR_PTR, BIO_ADDRINFO_address, (const GO_BIO_ADDRINFO_PTR ai), (ai))                                                                                                                                                             \
    DEFINEFUNC_1_1(int, BIO_closesocket, (int sock), (sock))                                                                                                                                                                                                \
    DEFINEFUNC_1_1(int, BIO_socket_nbio, (int sock, int mode), (sock, mode))                                                                                                                                                                                \
    DEFINEFUNC_1_1(void, BIO_ADDRINFO_free, (GO_BIO_ADDRINFO_PTR ai), (ai))                                                                                                                                                                                 \
    DEFINEFUNC_1_1(GO_BIO_PTR, BIO_new, (const GO_BIO_METHOD_PTR type), (type))                                                                                                                                                                             \
    DEFINEFUNC_1_1(GO_BIO_METHOD_PTR, BIO_s_socket, (void), ())                                                                                                                                                                                             \
    DEFINEFUNC(long, BIO_int_ctrl, (GO_BIO_PTR bp, int cmd, long larg, int iarg), (bp, cmd, larg, iarg))                                                                                                                                                    \
    DEFINEFUNC(long, BIO_ctrl, (GO_BIO_PTR bp, int cmd, long larg, void *parg), (bp, cmd, larg, parg))                                                                                                                                                      \
    DEFINEFUNC(void, BIO_free_all, (GO_BIO_PTR a), (a))

// Define pointers to all the used OpenSSL functions.
// Calling C function pointers from Go is currently not supported.
// It is possible to circumvent this by using a C function wrapper.
// https://pkg.go.dev/cmd/cgo
#define DEFINEFUNC(ret, func, args, argscall) \
    extern ret(*_g_##func) args;              \
    static inline ret go_openssl_##func args  \
    {                                         \
        return _g_##func argscall;            \
    }
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1_1(ret, func, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall) \
    DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall) \
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
