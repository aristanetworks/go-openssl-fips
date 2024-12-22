// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t

#include "libssl_shim.h"

// Suppress warnings about unused parameters.
#define UNUSED(x) (void)(x)

static inline void
go_openssl_do_leak_check(void)
{
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if (defined(__SANITIZE_ADDRESS__) && __SANITIZE_ADDRESS__) ||	\
    __has_feature(address_sanitizer)
    extern void __lsan_do_leak_check(void);
    __lsan_do_leak_check();
#endif
}

int go_openssl_fips_enabled(void* handle);
int go_openssl_version_major(void* handle);
int go_openssl_version_minor(void* handle);
int go_openssl_version_patch(void* handle);
int go_openssl_thread_setup(void);
void go_openssl_load_functions(void* handle, unsigned int major, unsigned int minor, unsigned int patch);
GO_BIO_PTR go_openssl_create_bio(const char *hostname, const char *port, int family, int mode);
int go_openssl_dial_host(GO_SSL_PTR ssl, const char *hostname, const char *port, int family, int mode);
int go_openssl_ssl_configure(GO_SSL_PTR ssl, const char *hostname);
int go_openssl_ssl_configure_sock(GO_SSL_PTR ssl, const char *hostname, int sockfd);
int go_openssl_ssl_configure_bio(GO_SSL_PTR ssl, GO_BIO_PTR bio, const char *hostname);
int go_openssl_set_h2_alpn(GO_SSL_CTX_PTR ctx);
int check_alpn_status(GO_SSL_PTR ssl, char *selected_proto, int *selected_len);