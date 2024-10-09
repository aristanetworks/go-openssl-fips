// This header file describes the OpenSSL ABI as built for use in Go.

#include <stdlib.h> // size_t

#include "libssl_shim.h"

// Suppress warnings about unused parameters.
#define UNUSED(x) (void)(x)

int go_openssl_fips_enabled(void* handle);
int go_openssl_version_major(void* handle);
int go_openssl_version_minor(void* handle);
int go_openssl_version_patch(void* handle);
void go_libssl_load_functions(void* handle, unsigned int major, unsigned int minor, unsigned int patch);
