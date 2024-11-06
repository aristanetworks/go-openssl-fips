#include "golibssl.h"

#define GO_SOCK_STREAM 1

/* Helper function to create a BIO connected to the server */
/* Borrowed from: https://github.com/openssl/openssl/blob/7ed6de997f62466271ef7ff6016026e1fdc76963/demos/guide/tls-client-non-block.c#L30 */
GO_BIO_PTR go_openssl_create_socket_bio(const char *hostname, const char *port, int family, int mode)
{
    int sock = -1;
    GO_BIO_ADDRINFO_PTR res;
    GO_BIO_ADDRINFO_PTR ai = NULL;
    GO_BIO_PTR bio;

    /*
     * Lookup IP address info for the server.
     */
    if (!go_openssl_BIO_lookup_ex(hostname, port, GO_BIO_LOOKUP_CLIENT, family, GO_SOCK_STREAM, 0,
                       &res))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (ai = res; ai != NULL; ai = go_openssl_BIO_ADDRINFO_next(ai)) {
        /*
         * Create a TCP socket. We could equally use non-OpenSSL calls such
         * as "socket" here for this and the subsequent connect and close
         * functions. But for portability reasons and also so that we get
         * errors on the OpenSSL stack in the event of a failure we use
         * OpenSSL's versions of these functions.
         */
        sock = go_openssl_BIO_socket(go_openssl_BIO_ADDRINFO_family(ai), GO_SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        if (!go_openssl_BIO_connect(sock, go_openssl_BIO_ADDRINFO_address(ai), GO_BIO_SOCK_NODELAY|GO_BIO_SOCK_KEEPALIVE)) {
            go_openssl_BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* Set to nonblocking mode */
        if (!go_openssl_BIO_socket_nbio(sock, mode)) {
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
    bio = go_openssl_BIO_new(go_openssl_BIO_s_socket());
    if (bio == NULL) {
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
    // go_openssl_BIO_set_fd(bio, sock, GO_BIO_CLOSE);
    go_openssl_BIO_int_ctrl(bio, GO_BIO_C_SET_FD, GO_BIO_CLOSE, sock);

    return bio;
}
