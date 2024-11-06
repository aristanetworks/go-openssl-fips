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
GO_BIO_PTR go_openssl_create_socket_bio(const char *hostname, const char *port, int family, int mode);
