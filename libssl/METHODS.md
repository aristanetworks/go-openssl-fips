# OpenSSL TLS Methods Compatiability Matrix

| Method Name | OpenSSL 3.x | OpenSSL 1.1.1 | OpenSSL 1.1.0 | OpenSSL 1.0.x |
|-------------|-------------|---------------|---------------|---------------|
| BIO_lookup_ex | int BIO_lookup_ex(const char *host, const char *service, int lookup_type, int family, int socktype, int protocol, BIO_ADDRINFO **res) | **NOT AVAILABLE** | **NOT AVAILABLE** | **NOT AVAILABLE** |
| BIO_ADDRINFO_next | const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *ai) | const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *ai) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| BIO_socket | int BIO_socket(int domain, int type, int protocol, int options) | int BIO_socket(int domain, int type, int protocol, int options) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| BIO_connect | int BIO_connect(int sock, const BIO_ADDR *addr, int options) | int BIO_connect(int sock, const BIO_ADDR *addr, int options) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| BIO_closesocket | int BIO_closesocket(int sock) | int BIO_closesocket(int sock) | int BIO_closesocket(int sock) | int BIO_closesocket(int sock) |
| BIO_ADDRINFO_free | void BIO_ADDRINFO_free(BIO_ADDRINFO *ai) | void BIO_ADDRINFO_free(BIO_ADDRINFO *ai) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| BIO_new | BIO *BIO_new(const BIO_METHOD *type) | BIO *BIO_new(const BIO_METHOD *type) | BIO *BIO_new(const BIO_METHOD *type) | BIO *BIO_new(const BIO_METHOD *type) |
| BIO_set_fd | long BIO_set_fd(BIO *b, int fd, long close_flag) | long BIO_set_fd(BIO *b, int fd, long close_flag) | long BIO_set_fd(BIO *b, int fd, long close_flag) | long BIO_set_fd(BIO *b, int fd, long close_flag) |
| SSL_CTX_new | SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) | SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) | SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) | SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth) |
| SSL_CTX_set_verify | void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback) | void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback) | void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback) | void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*callback)(int, X509_STORE_CTX *)) |
| SSL_CTX_set_default_verify_paths | int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) | int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) | int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) | int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) |
| SSL_CTX_set_min_proto_version | int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version) | int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| SSL_new | SSL *SSL_new(SSL_CTX *ctx) | SSL *SSL_new(SSL_CTX *ctx) | SSL *SSL_new(SSL_CTX *ctx) | SSL *SSL_new(SSL_CTX *ctx) |
| SSL_set_bio | void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio) | void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio) | void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio) | void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio) |
| SSL_set_tlsext_host_name | int SSL_set_tlsext_host_name(SSL *s, const char *name) | int SSL_set_tlsext_host_name(SSL *s, const char *name) | int SSL_set_tlsext_host_name(SSL *s, const char *name) | long SSL_set_tlsext_host_name(SSL *s, const char *name) |
| SSL_set1_host | int SSL_set1_host(SSL *s, const char *hostname) | int SSL_set1_host(SSL *s, const char *hostname) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| SSL_connect | int SSL_connect(SSL *ssl) | int SSL_connect(SSL *ssl) | int SSL_connect(SSL *ssl) | int SSL_connect(SSL *ssl) |
| SSL_get_verify_result | long SSL_get_verify_result(const SSL *ssl) | long SSL_get_verify_result(const SSL *ssl) | long SSL_get_verify_result(const SSL *ssl) | long SSL_get_verify_result(const SSL *ssl) |
| SSL_write_ex | int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written) | int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| SSL_read_ex | int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes) | int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes) | **NOT AVAILABLE** | **NOT AVAILABLE** |
| SSL_get_error | int SSL_get_error(const SSL *s, int ret) | int SSL_get_error(const SSL *s, int ret) | int SSL_get_error(const SSL *s, int ret) | int SSL_get_error(const SSL *s, int ret) |
| SSL_shutdown | int SSL_shutdown(SSL *ssl) | int SSL_shutdown(SSL *ssl) | int SSL_shutdown(SSL *ssl) | int SSL_shutdown(SSL *ssl) |
| SSL_free | void SSL_free(SSL *ssl) | void SSL_free(SSL *ssl) | void SSL_free(SSL *ssl) | void SSL_free(SSL *ssl) |
| SSL_CTX_free | void SSL_CTX_free(SSL_CTX *ctx) | void SSL_CTX_free(SSL_CTX *ctx) | void SSL_CTX_free(SSL_CTX *ctx) | void SSL_CTX_free(SSL_CTX *ctx) |
| ERR_print_errors_fp | void ERR_print_errors_fp(FILE *fp) | void ERR_print_errors_fp(FILE *fp) | void ERR_print_errors_fp(FILE *fp) | void ERR_print_errors_fp(FILE *fp) |

# OpenSSL Backwards Compatiability Matrix
| New Method Name | Old Method Name | OpenSSL 1.1.0 and earlier | OpenSSL 1.0.x |
|-----------------|-----------------|---------------------------|---------------|
| BIO_lookup_ex | getaddrinfo (system call) | int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) | int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) |
| BIO_ADDRINFO_next | - | Use standard `struct addrinfo *ai->ai_next` | Use standard `struct addrinfo *ai->ai_next` |
| BIO_socket | socket (system call) | int socket(int domain, int type, int protocol) | int socket(int domain, int type, int protocol) |
| BIO_connect | connect (system call) | int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) | int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) |
| SSL_CTX_set_min_proto_version | SSL_CTX_set_options | long SSL_CTX_set_options(SSL_CTX *ctx, long options) | long SSL_CTX_set_options(SSL_CTX *ctx, long options) |
| SSL_set1_host | SSL_set_hostflags + SSL_set_hostname | void SSL_set_hostflags(SSL *s, unsigned int flags)<br>int SSL_set_hostname(SSL *s, const char *hostname) | **NOT AVAILABLE** (use X509_VERIFY_PARAM_set1_host) |
| SSL_write_ex | SSL_write | int SSL_write(SSL *ssl, const void *buf, int num) | int SSL_write(SSL *ssl, const void *buf, int num) |
| SSL_read_ex | SSL_read | int SSL_read(SSL *ssl, void *buf, int num) | int SSL_read(SSL *ssl, void *buf, int num) |


Most of the backwards incompatabilities are within the BIO socket setup methods. Instead, we can create this socket using Golang, but will come at the cost of not getting errors on the OpenSSL stack in the event of a failure.
