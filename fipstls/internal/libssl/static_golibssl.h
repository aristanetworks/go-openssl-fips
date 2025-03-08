// This header file describes the OpenSSL ABI as built for use in Go.
// +build static

#include <stdlib.h> // size_t

#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include "flags.h"

// Suppress warnings about unused parameters.
#define UNUSED(x) (void)(x)

static inline void
do_leak_check(void)
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

// GO_OPENSSL_DEBUGLOG traces  helper function calls to stderr
#define GO_OPENSSL_DEBUGLOG(enabled, ...) \
    do                                    \
    {                                     \
        if (enabled)                      \
        {                                 \
            fprintf(stderr, __VA_ARGS__); \
        }                                 \
    } while (0)

BIO *create_bio(const char *hostname, const char *port, int family, int mode, int trace);
int ctx_configure(SSL_CTX *ctx, long minTLS, long maxTLS, long options, int verifyMode, const char *nextProto, const char *caPath, const char *caFile, const char *certFile, const char *keyFile, int trace);
int ssl_configure(SSL *ssl, const char *hostname, int trace);
int ssl_configure_bio(SSL *ssl, BIO *bio, const char *hostname, int trace);
int set_h2_alpn(SSL_CTX *ctx, int trace);
int check_alpn_status(SSL *ssl, char *selected_proto, int *selected_len, int trace);