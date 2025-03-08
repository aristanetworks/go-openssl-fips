// +build static

#include "static_golibssl.h"

int ctx_configure(SSL_CTX *ctx, long minTLS, long maxTLS, long options,
                  int verifyMode, const char *nextProto,
                  const char *caPath, const char *caFile,
                  const char *certFile, const char *keyFile, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] ctx_configure...\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_options...\n");
    int oldMask = SSL_CTX_ctrl(ctx, GO_SSL_CTRL_OPTIONS, 0, NULL);
    int newMask = SSL_CTX_ctrl(ctx, GO_SSL_CTRL_OPTIONS, options, NULL);
    if (oldMask != 0 && oldMask == newMask)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_options failed!\n");
        return 1;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_options succeeded!\n");
    if (strncmp(nextProto, "h2", 2) == 0 && set_h2_alpn(ctx, trace) != 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_alpn_protos failed!\n");
        return 1;
    }

    // Configure certificate if provided
    if (certFile != NULL && strlen(certFile) > 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_use_certificate_chain with 'certFile=%s'...\n",
                            certFile);
        if (SSL_CTX_use_certificate_chain_file(ctx, certFile) != 1)
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
        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, X509_FILETYPE_PEM) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_use_PrivateKey_file failed!\n");
            return 1;
        }
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_use_PrivateKey_file succeeded!\n");
    }

    // no callback
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_verify with 'verifyMode=%d'...\n",
                        verifyMode);
    SSL_CTX_set_verify(ctx, verifyMode, NULL);
    if (minTLS != 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_min_proto_version with 'minTLS=%ld'...\n",
                            minTLS);
        if (SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, minTLS, NULL) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_min_proto_version failed!\n");
            return 1;
        }
    }
    if (maxTLS != 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_max_proto_version with 'maxTLS=%ld'...\n",
                            maxTLS);
        if (SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, maxTLS, NULL) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_max_proto_version failed!\n");
            return 1;
        }
    }
    // if either of these are empty, use default verify paths
    if (caPath != NULL && caFile != NULL && strlen(caPath) > 0 && strlen(caFile) > 0)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_load_verify_locations with 'caPath=%s' and 'caFile=%s'...\n", caPath, caFile);
        if (SSL_CTX_load_verify_locations(ctx, caFile, caPath) != 1)
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_load_verify_locations failed!\n");
            return 1;
        }
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_load_verify_locations succeeded!\n");
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] ctx_configure succeeded!\n");
        return 0;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_default_verify_paths...\n");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_CTX_set_default_verify_paths failed!\n");
        return 1;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_default_verify_paths succeeded!\n");
    return 0;
}

// ssl_configure_bio configures the ssl connection with BIO.
int ssl_configure_bio(SSL *ssl, BIO *bio, const char *hostname, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] ssl_configure_bio...\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_bio with 'host=%s'...\n", hostname);
    ERR_clear_error();
    SSL_set_bio(ssl, bio, bio);
    return ssl_configure(ssl, hostname, trace);
}

int ssl_configure(SSL *ssl, const char *hostname, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] ssl_configure...\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_connect_state with 'host=%s'...\n", hostname);
    int r;
    SSL_set_connect_state(ssl);
    // TODO: since we know the hostname during ssl creation, we should make this a configuration
    // option
    // SSL_set_tlsext_hostname sets the SNI hostname
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_tlsext_hostname with 'host=%s'...\n", hostname);
    r = SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME,
                 TLSEXT_NAMETYPE_host_name, (void *)hostname);
    if (r != 1)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_set_tlsext_hostname failed!\n");
        return r;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set_tlsext_hostname succeeded!\n");

    // SSL_set1_host sets the hostname for certificate verification
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set1_host with 'host=%s'...\n", hostname);
    r = SSL_set1_host(ssl, hostname);
    if (r != 1)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] SSL_set1_host failed!\n");
        return r;
    }
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_set1_host succeeded!\n");
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] ssl_configure succeeded!\n");
    return 0;
}

/* Helper function to create a BIO connected to the server */
/* Borrowed from: https://github.com/openssl/openssl/blob/7ed6de997f62466271ef7ff6016026e1fdc76963/demos/guide/tls-client-non-block.c#L30 */

BIO *create_bio(const char *hostname, const char *port, int family, int mode, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] create_bio with 'host=%s:%s'...\n",
                        hostname, port);

    int sock = -1;
    BIO_ADDRINFO *res;
    BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    /*
     * Lookup IP address info for the server.
     */
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_lookup_ex with 'host=%s:%s'...\n",
                        hostname, port);
    if (!BIO_lookup_ex(hostname, port, GO_BIO_LOOKUP_CLIENT, family,
                       GO_OPENSSL_SOCK_STREAM, 0, &res))
        return NULL;
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_lookup_ex succeeded!\n");
    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai))
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
        sock = BIO_socket(BIO_ADDRINFO_family(ai), GO_OPENSSL_SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_connect...\n");
        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai),
                         GO_BIO_SOCK_NODELAY | GO_BIO_SOCK_KEEPALIVE))
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] BIO_connect failed!\n");
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* Set to nonblocking mode */
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_socket_nbio with 'mode=%d'...\n", mode);
        if (!BIO_socket_nbio(sock, mode))
        {
            GO_OPENSSL_DEBUGLOG(trace, "[ERROR] BIO_socket_nbio failed!\n", mode);
            sock = -1;
            continue;
        }

        /* We have a connected socket so break out of the loop */
        break;
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(res);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket */
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] BIO_new...\n");
    bio = BIO_new(BIO_s_socket());
    if (bio == NULL)
    {
        GO_OPENSSL_DEBUGLOG(trace, "[ERROR] BIO_new failed!\n");
        BIO_closesocket(sock);
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
    // BIO_set_fd(bio, sock, GO_BIO_CLOSE);
    BIO_int_ctrl(bio, BIO_C_SET_FD, BIO_CLOSE, sock);
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] create_bio succeeded!\n");
    return bio;
}

static const unsigned char h2_proto[] = {2, 'h', '2', '\0'};

int set_h2_alpn(SSL_CTX *ctx, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_CTX_set_alpn_protos with 'h2_proto=%s'...\n",
                        h2_proto);
    return SSL_CTX_set_alpn_protos(ctx, h2_proto, 3);
}

int check_alpn_status(SSL *ssl, char *selected_proto, int *selected_len, int trace)
{
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] check_alpn_status...\n");
    const unsigned char *proto;
    unsigned int len;
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_get0_alpn_selected...\n");
    SSL_get0_alpn_selected(ssl, &proto, &len);

    if (len > 0 && len < 256)
    { // Add safety bound
        memcpy(selected_proto, proto, len);
        *selected_len = len;
        GO_OPENSSL_DEBUGLOG(trace, "[INFO] SSL_get0_alpn_selected found 'selected_proto=%s'!\n",
                            selected_proto);
        return len;
    }
    *selected_len = 0;
    GO_OPENSSL_DEBUGLOG(trace, "[INFO] check_alpn_status succeeded!\n");
    return 0;
}