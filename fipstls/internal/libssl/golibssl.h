// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t

#include "shim.h"

// Suppress warnings about unused parameters.
#define UNUSED(x) (void)(x)

static inline void
go_openssl_do_leak_check(void)
{
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if (defined(__SANITIZE_ADDRESS__) && __SANITIZE_ADDRESS__) || \
    __has_feature(address_sanitizer)
    extern void __lsan_do_leak_check(void);
    __lsan_do_leak_check();
#endif
}

#define GO_OPENSSL_SOCK_STREAM 1

// GO_OPENSSL_DEBUGLOG traces go_openssl_ helper function calls to stderr
#define GO_OPENSSL_DEBUGLOG(enabled, ...) \
    do                                    \
    {                                     \
        if (enabled)                      \
        {                                 \
            fprintf(stderr, __VA_ARGS__); \
        }                                 \
    } while (0)

int go_openssl_fips_enabled(void *handle);
int go_openssl_version_major(void *handle);
int go_openssl_version_minor(void *handle);
int go_openssl_version_patch(void *handle);
int go_openssl_thread_setup(void);
void go_openssl_load_functions(void *handle, unsigned int major, unsigned int minor, unsigned int patch);
GO_BIO_PTR go_openssl_create_bio(const char *hostname, const char *port, int family, int mode, int trace);
int go_openssl_ctx_configure(GO_SSL_CTX_PTR ctx, long minTLS, long maxTLS, long options, int verifyMode, const char *nextProto, const char *caPath, const char *caFile, const char *certFile, const char *keyFile, int trace);
int go_openssl_ssl_configure(GO_SSL_PTR ssl, const char *hostname, int trace);
int go_openssl_ssl_configure_bio(GO_SSL_PTR ssl, GO_BIO_PTR bio, const char *hostname, int trace);
int go_openssl_set_h2_alpn(GO_SSL_CTX_PTR ctx, int trace);
int go_openssl_check_alpn_status(GO_SSL_PTR ssl, char *selected_proto, int *selected_len, int trace);