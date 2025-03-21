// go:build unix

#include "golibssl.h"

#include <dlfcn.h>  // dlsym
#include <stdio.h>  // fprintf
#include <stdlib.h> // abort
#include <string.h>

// Approach taken from .Net System.Security.Cryptography.Native
// https://github.com/dotnet/runtime/blob/f64246ce08fb7a58221b2b7c8e68f69c02522b0d/src/libraries/Native/Unix/System.Security.Cryptography.Native/opensslshim.c

#define DEFINEFUNC(ret, func, args, argscall) ret(*_g_##func) args;
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1(ret, func, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_1_1_1(ret, func, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_3_0(ret, func, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall) DEFINEFUNC(ret, func, args, argscall)
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall) DEFINEFUNC(ret, func, args, argscall)

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

int go_openssl_fips_enabled(void *handle)
{
    // For OpenSSL 1.x.
    int (*FIPS_mode)(void);
    FIPS_mode = (int (*)(void))dlsym(handle, "FIPS_mode");
    if (FIPS_mode != NULL)
        return FIPS_mode();

    // For OpenSSL 3.x.
    int (*EVP_default_properties_is_fips_enabled)(void *);
    int (*OSSL_PROVIDER_available)(void *, const char *);
    EVP_default_properties_is_fips_enabled = (int (*)(void *))dlsym(handle, "EVP_default_properties_is_fips_enabled");
    OSSL_PROVIDER_available = (int (*)(void *, const char *))dlsym(handle, "OSSL_PROVIDER_available");
    if (EVP_default_properties_is_fips_enabled != NULL && OSSL_PROVIDER_available != NULL &&
        EVP_default_properties_is_fips_enabled(NULL) == 1 && OSSL_PROVIDER_available(NULL, "fips") == 1)
        return 1;

    return 0;
}

// Load all the functions stored in FOR_ALL_LIBSSL_FUNCTIONS
// and assign them to their corresponding function pointer
// defined in goopenssl.h.
void go_openssl_load_functions(void *handle, unsigned int major, unsigned int minor, unsigned int patch)
{
#define DEFINEFUNC_INTERNAL(name, func)                                                                    \
    _g_##name = dlsym(handle, func);                                                                       \
    if (_g_##name == NULL)                                                                                 \
    {                                                                                                      \
        fprintf(stderr, "Cannot get required symbol " #func " from libssl version %u.%u\n", major, minor); \
        abort();                                                                                           \
    }
#define DEFINEFUNC(ret, func, args, argscall) \
    DEFINEFUNC_INTERNAL(func, #func)
#define DEFINEFUNC_LEGACY_1_1(ret, func, args, argscall) \
    if (major == 1 && minor == 1)                        \
    {                                                    \
        DEFINEFUNC_INTERNAL(func, #func)                 \
    }
#define DEFINEFUNC_LEGACY_1_0(ret, func, args, argscall) \
    if (major == 1 && minor == 0)                        \
    {                                                    \
        DEFINEFUNC_INTERNAL(func, #func)                 \
    }
#define DEFINEFUNC_LEGACY_1(ret, func, args, argscall) \
    if (major == 1)                                    \
    {                                                  \
        DEFINEFUNC_INTERNAL(func, #func)               \
    }
#define DEFINEFUNC_1_1(ret, func, args, argscall) \
    if (major == 3 || (major == 1 && minor == 1)) \
    {                                             \
        DEFINEFUNC_INTERNAL(func, #func)          \
    }
#define DEFINEFUNC_1_1_1(ret, func, args, argscall)             \
    if (major == 3 || (major == 1 && minor == 1 && patch == 1)) \
    {                                                           \
        DEFINEFUNC_INTERNAL(func, #func)                        \
    }
#define DEFINEFUNC_3_0(ret, func, args, argscall) \
    if (major == 3)                               \
    {                                             \
        DEFINEFUNC_INTERNAL(func, #func)          \
    }
#define DEFINEFUNC_RENAMED_1_1(ret, func, oldfunc, args, argscall) \
    if (major == 1 && minor == 0)                                  \
    {                                                              \
        DEFINEFUNC_INTERNAL(func, #oldfunc)                        \
    }                                                              \
    else                                                           \
    {                                                              \
        DEFINEFUNC_INTERNAL(func, #func)                           \
    }
#define DEFINEFUNC_RENAMED_3_0(ret, func, oldfunc, args, argscall) \
    if (major == 1)                                                \
    {                                                              \
        DEFINEFUNC_INTERNAL(func, #oldfunc)                        \
    }                                                              \
    else                                                           \
    {                                                              \
        DEFINEFUNC_INTERNAL(func, #func)                           \
    }

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
}

static unsigned long
version_num(void *handle)
{
    unsigned long (*fn)(void);
    // OPENSSL_version_num is defined in OpenSSL 1.1.0 and 1.1.1.
    fn = (unsigned long (*)(void))dlsym(handle, "OpenSSL_version_num");
    if (fn != NULL)
        return fn();

    // SSLeay is defined in OpenSSL 1.0.2.
    fn = (unsigned long (*)(void))dlsym(handle, "SSLeay");
    if (fn != NULL)
        return fn();

    return 0;
}

int go_openssl_version_major(void *handle)
{
    unsigned int (*fn)(void);
    // OPENSSL_version_major is supported since OpenSSL 3.
    fn = (unsigned int (*)(void))dlsym(handle, "OPENSSL_version_major");
    if (fn != NULL)
        return (int)fn();

    // If OPENSSL_version_major is not defined, try with OpenSSL 1 functions.
    unsigned long num = version_num(handle);
    if (num < 0x10000000L || num >= 0x20000000L)
        return -1;

    return 1;
}

int go_openssl_version_minor(void *handle)
{
    unsigned int (*fn)(void);
    // OPENSSL_version_minor is supported since OpenSSL 3.
    fn = (unsigned int (*)(void))dlsym(handle, "OPENSSL_version_minor");
    if (fn != NULL)
        return (int)fn();

    // If OPENSSL_version_minor is not defined, try with OpenSSL 1 functions.
    unsigned long num = version_num(handle);
    // OpenSSL version number follows this schema:
    // MNNFFPPS: major minor fix patch status.
    if (num < 0x10000000L || num >= 0x10200000L)
    {
        // We only support minor version 0 and 1,
        // so there is no need to implement an algorithm
        // that decodes the version number into individual components.
        return -1;
    }

    if (num >= 0x10100000L)
        return 1;

    return 0;
}

int go_openssl_version_patch(void *handle)
{
    unsigned int (*fn)(void);
    // OPENSSL_version_patch is supported since OpenSSL 3.
    fn = (unsigned int (*)(void))dlsym(handle, "OPENSSL_version_patch");
    if (fn != NULL)
        return (int)fn();

    // If OPENSSL_version_patch is not defined, try with OpenSSL 1 functions.
    unsigned long num = version_num(handle);
    // OpenSSL version number follows this schema:
    // MNNFFPPS: major minor fix patch status.
    if (num < 0x10000000L || num >= 0x10200000L)
    {
        // We only support minor version 0 and 1,
        // so there is no need to implement an algorithm
        // that decodes the version number into individual components.
        return -1;
    }

    return (num >> 12) & 0xff;
}

int go_openssl_ctx_configure(GO_SSL_CTX_PTR ctx, long minTLS, long maxTLS, long options,
                             int verifyMode, const char *nextProto,
                             const char *caPath, const char *caFile,
                             const char *certFile, const char *keyFile, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_ctx_configure...\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_options...\n");
    int oldMask = go_openssl_SSL_CTX_ctrl(ctx, GO_SSL_CTRL_OPTIONS, 0, NULL);
    int newMask = go_openssl_SSL_CTX_ctrl(ctx, GO_SSL_CTRL_OPTIONS, options, NULL);
    if (oldMask != 0 && oldMask == newMask)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_options failed!\n");
        return 1;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_options succeeded!\n");
    if (strncmp(nextProto, "h2", 2) == 0 && go_openssl_set_h2_alpn(ctx, trace) != 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_alpn_protos failed!\n");
        return 1;
    }

    // Configure certificate if provided
    if (certFile != NULL && strlen(certFile) > 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_use_certificate_chain with 'certFile=%s'...\n",
                            certFile);
        if (go_openssl_SSL_CTX_use_certificate_chain_file(ctx, certFile) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_use_certificate_chain failed!\n");
            return 1;
        }
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_use_certificate_chain succeeded!\n");
    }

    // Configure private key if provided
    if (keyFile != NULL && strlen(keyFile) > 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_use_PrivateKey_file with 'keyFile=%s'...\n",
                            keyFile);
        if (go_openssl_SSL_CTX_use_PrivateKey_file(ctx, keyFile, GO_X509_FILETYPE_PEM) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_use_PrivateKey_file failed!\n");
            return 1;
        }
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_use_PrivateKey_file succeeded!\n");
    }

    // no callback
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_verify with 'verifyMode=%d'...\n",
                        verifyMode);
    go_openssl_SSL_CTX_set_verify(ctx, verifyMode, NULL);
    if (minTLS != 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_min_proto_version with 'minTLS=%ld'...\n",
                            minTLS);
        if (go_openssl_SSL_CTX_ctrl(ctx, GO_SSL_CTRL_SET_MIN_PROTO_VERSION, minTLS, NULL) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_min_proto_version failed!\n");
            return 1;
        }
    }
    if (maxTLS != 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_max_proto_version with 'maxTLS=%ld'...\n",
                            maxTLS);
        if (go_openssl_SSL_CTX_ctrl(ctx, GO_SSL_CTRL_SET_MAX_PROTO_VERSION, maxTLS, NULL) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_max_proto_version failed!\n");
            return 1;
        }
    }
    // if either of these are empty, use default verify paths
    if (caPath != NULL && caFile != NULL && strlen(caPath) > 0 && strlen(caFile) > 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_load_verify_locations with 'caPath=%s' and 'caFile=%s'...\n", caPath, caFile);
        if (go_openssl_SSL_CTX_load_verify_locations(ctx, caFile, caPath) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_load_verify_locations failed!\n");
            return 1;
        }
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_load_verify_locations succeeded!\n");
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_ctx_configure succeeded!\n");
        return 0;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_default_verify_paths...\n");
    if (go_openssl_SSL_CTX_set_default_verify_paths(ctx) != 1)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_default_verify_paths failed!\n");
        return 1;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_default_verify_paths succeeded!\n");
    return 0;
}

// go_openssl_ssl_configure_bio configures the ssl connection with BIO.
int go_openssl_ssl_configure_bio(GO_SSL_PTR ssl, GO_BIO_PTR bio, const char *hostname, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_ssl_configure_bio...\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_bio with 'host=%s'...\n", hostname);
    go_openssl_ERR_clear_error();
    go_openssl_SSL_set_bio(ssl, bio, bio);
    return go_openssl_ssl_configure(ssl, hostname, trace);
}

int go_openssl_ssl_configure(GO_SSL_PTR ssl, const char *hostname, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_ssl_configure...\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_connect_state with 'host=%s'...\n", hostname);
    int r;
    go_openssl_SSL_set_connect_state(ssl);
    // TODO: since we know the hostname during ssl creation, we should make this a configuration
    // option
    // SSL_set_tlsext_hostname sets the SNI hostname
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_tlsext_hostname with 'host=%s'...\n", hostname);
    r = go_openssl_SSL_ctrl(ssl, GO_SSL_CTRL_SET_TLSEXT_HOSTNAME,
                            GO_TLSEXT_NAMETYPE_host_name, (void *)hostname);
    if (r != 1)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_set_tlsext_hostname failed!\n");
        return r;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_tlsext_hostname succeeded!\n");

    // SSL_set1_host sets the hostname for certificate verification
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set1_host with 'host=%s'...\n", hostname);
    r = go_openssl_SSL_set1_host(ssl, hostname);
    if (r != 1)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_set1_host failed!\n");
        return r;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set1_host succeeded!\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_ssl_configure succeeded!\n");
    return 0;
}

/* Helper function to create a BIO connected to the server */
/* Borrowed from: https://github.com/openssl/openssl/blob/7ed6de997f62466271ef7ff6016026e1fdc76963/demos/guide/tls-client-non-block.c#L30 */

GO_BIO_PTR
go_openssl_create_bio(const char *hostname, const char *port, int family, int mode, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_create_bio with 'host=%s:%s'...\n",
                        hostname, port);

    int sock = -1;
    GO_BIO_ADDRINFO_PTR res;
    GO_BIO_ADDRINFO_PTR ai = NULL;
    GO_BIO_PTR bio;

    /*
     * Lookup IP address info for the server.
     */
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_lookup_ex with 'host=%s:%s'...\n",
                        hostname, port);
    if (!go_openssl_BIO_lookup_ex(hostname, port, GO_BIO_LOOKUP_CLIENT, family,
                                  GO_OPENSSL_SOCK_STREAM, 0, &res))
        return NULL;
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_lookup_ex succeeded!\n");
    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (ai = res; ai != NULL; ai = go_openssl_BIO_ADDRINFO_next(ai))
    {
        /*
         * Create a TCP socket. We could equally use non-OpenSSL calls such
         * as "socket" here for this and the subsequent connect and close
         * functions. But for portability reasons and also so that we get
         * errors on the OpenSSL stack in the event of a failure we use
         * OpenSSL's versions of these functions.
         */
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_ADDRINFO_family with 'GO_OPENSSL_SOCK_STREAM=%d'...\n",
                            GO_OPENSSL_SOCK_STREAM);
        sock = go_openssl_BIO_socket(go_openssl_BIO_ADDRINFO_family(ai), GO_OPENSSL_SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_connect...\n");
        if (!go_openssl_BIO_connect(sock, go_openssl_BIO_ADDRINFO_address(ai),
                                    GO_BIO_SOCK_NODELAY | GO_BIO_SOCK_KEEPALIVE))
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] BIO_connect failed!\n");
            go_openssl_BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* Set to nonblocking mode */
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_socket_nbio with 'mode=%d'...\n", mode);
        if (!go_openssl_BIO_socket_nbio(sock, mode))
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] BIO_socket_nbio failed!\n", mode);
            sock = -1;
            continue;
        }

        /* We have a connected socket so break out of the loop */
        break;
    }

    /* Free the address information resources we allocated earlier */
    go_openssl_BIO_ADDRINFO_free(res);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket */
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_new...\n");
    bio = go_openssl_BIO_new(go_openssl_BIO_s_socket());
    if (bio == NULL)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] BIO_new failed!\n");
        go_openssl_BIO_closesocket(sock);
        return NULL;
    }

    /*
     * Associate the newly created BIO with the underlying socket. By
     * passing BIO_CLOSE here the socket will be automatically closed when
     * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which
     * case you must close the socket explicitly when it is no longer
     * needed.
     */
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_set_fd...\n");
    // go_openssl_BIO_set_fd(bio, sock, GO_BIO_CLOSE);
    go_openssl_BIO_int_ctrl(bio, GO_BIO_C_SET_FD, GO_BIO_CLOSE, sock);
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_create_bio succeeded!\n");
    return bio;
}

static const unsigned char h2_proto[] = {2, 'h', '2', '\0'};

int go_openssl_set_h2_alpn(GO_SSL_CTX_PTR ctx, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_alpn_protos with 'h2_proto=%s'...\n",
                        h2_proto);
    return go_openssl_SSL_CTX_set_alpn_protos(ctx, h2_proto, 3);
}

int go_openssl_check_alpn_status(GO_SSL_PTR ssl, char *selected_proto, int *selected_len, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_check_alpn_status...\n");
    const unsigned char *proto;
    unsigned int len;
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_get0_alpn_selected...\n");
    go_openssl_SSL_get0_alpn_selected(ssl, &proto, &len);

    if (len > 0 && len < 256)
    { // Add safety bound
        memcpy(selected_proto, proto, len);
        *selected_len = len;
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_get0_alpn_selected found 'selected_proto=%s'!\n",
                            selected_proto);
        return len;
    }
    *selected_len = 0;
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] go_openssl_check_alpn_status succeeded!\n");
    return 0;
}

typedef struct
{
    char *data;
    size_t size;
} param_info_st;

int go_openssl_get_provider_params(GO_OSSL_PROVIDER_PTR provider, param_info_st *info)
{
    int ret = 1;
    char *name = NULL;
    char *version = NULL;
    char *buildinfo = NULL;

    GO_OSSL_PARAM request[] = {
        {GO_OSSL_PROV_PARAM_NAME, GO_OSSL_PARAM_UTF8_PTR, &name, 0, 0},
        {GO_OSSL_PROV_PARAM_VERSION, GO_OSSL_PARAM_UTF8_PTR, &version, 0, 0},
        {GO_OSSL_PROV_PARAM_BUILDINFO, GO_OSSL_PARAM_UTF8_PTR, &buildinfo, 0, 0},
        {NULL, 0, NULL, 0, 0},
    };

    if (go_openssl_OSSL_PROVIDER_get_params(provider, request) <= 0)
    {
        snprintf(info->data, info->size, "Failed to get provider parameters");
        return ret;
    }

    snprintf(info->data, info->size,
             "%s, version: %s, build info: %s",
             name ? name : "(null)",
             version ? version : "(null)",
             buildinfo ? buildinfo : "(null)");

    return !ret;
}

int go_openssl_get_fips_provider_info(char *buf, size_t size)
{
    int ret = 1;
    if (!buf || size == 0)
    {
        return ret;
    }
    memset(buf, 0, sizeof(size));

    GO_OSSL_PROVIDER_PTR provider = go_openssl_OSSL_PROVIDER_try_load(NULL, GO_OSSL_PROV_FIPS_PREDEFINED_NAME, 1);
    if (!provider)
    {
        snprintf(buf, size, "FIPS provider not available");
        return ret;
    }

    param_info_st info = {buf, size};
    ret = go_openssl_get_provider_params(provider, &info);
    go_openssl_OSSL_PROVIDER_unload(provider);
    return ret;
}