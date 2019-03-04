#include <errno.h>
#include <stdbool.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "rho_buf.h"
#include "rho_fd.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_sock.h"
#include "rho_ssl.h"

#include "openssl/rho_openssl.h"

#define RHO_SSL_CIPHERS_DEFAULT \
    "AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:" \
    "AES128-GCM-SHA256:AES1280SHA256:AES128-SHA:" \
    "AES:" \
    "-SHA:" \
    "!aNULL:!eNULL:" \
    "!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:" \
    "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:" \
    "!KRB5-DES-CBC3-SHA"

enum rho_ssl_state {
    RHO_SSL_STATE_NEW = 1,
    RHO_SSL_STATE_CONNECTING,
    RHO_SSL_STATE_CONNECTED,
    RHO_SSL_STATE_CLOSED
};

/* TODO: reference to rho_ssl_params? */
struct rho_ssl_ctx {
    enum rho_ssl_mode   mode;
    SSL_CTX             *ctx;
};

struct rho_ssl {
    enum rho_ssl_state  state;
    SSL                 *ssl;
};

static ssize_t rho_ssl_sock_recv(struct rho_sock *sock, void *buf,
        size_t len);
static ssize_t rho_ssl_sock_send(struct rho_sock *sock, const void *buf, 
        size_t len);
static void rho_ssl_sock_destroy(struct rho_sock *sock);

static struct rho_sock_ops rho_ssl_sock_ops = {
    .recv = rho_ssl_sock_recv,
    .send = rho_ssl_sock_send,
    .destroy = rho_ssl_sock_destroy,
};

/*
 * SSL CONTEXT
 */

#if 0
/* TODO: add later */
static int
rho_ssl_passwd_cb(char *buf, int size, int rwflag, void *u)
{
    (void)rwflag;
    strncpy(buf, (char *)u, size);
    buf[size - 1] = '\0';
    return strlen(buf);
}
#endif

static const SSL_METHOD *
rho_ssl_protocol2method(enum rho_ssl_protocol protocol)
{
    switch (protocol) {
    case RHO_SSL_PROTOCOL_SSLv23:
        return SSLv23_method();  /* deprecated */
    case RHO_SSL_PROTOCOL_TLSv1:
        return TLSv1_method();
    case RHO_SSL_PROTOCOL_TLSv1_1:
        return TLSv1_1_method();
    case RHO_SSL_PROTOCOL_TLSv1_2:
        return TLSv1_2_method();
    default:
        rho_warn("unknown protocol '%d'", protocol);
        return NULL;
    }
}

static void
rho_ssl_ctx_set_key_and_cert_files(struct rho_ssl_ctx *r_ctx, const char *key_path, 
        const char *cert_path)
{
    SSL_CTX *ctx = r_ctx->ctx;

    /* 
     * TODO: keyfile password:
     *  SSL_CTX_set_default_passwd_cb(ctx, rho_ssl_passwd_cb);
     *  SSL_CTX_set_default_passwd_cb_userdata(ctx, sc->password);
     */

    if (1 != SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM))
        rho_openssl_die("Unable to use private key file '%s'", key_path);

    if (1 != SSL_CTX_use_certificate_chain_file(ctx, cert_path))
        rho_openssl_die("Unable to use certificate file '%s'", cert_path);

    if (!SSL_CTX_check_private_key(ctx))
        rho_openssl_die("Check private key failed");
}

static void
rho_ssl_ctx_set_ca_file(struct rho_ssl_ctx *r_ctx, const char *path)
{
    SSL_CTX *ctx = r_ctx->ctx;

    if (1 != SSL_CTX_load_verify_locations(ctx, path, NULL))
        rho_openssl_die("Unable to use CA file '%s'", path);
}

/* 
 * XXX: SSL offers a few other options, but they don't make sense
 * to me.
 */
static void
rho_ssl_ctx_set_verify(struct rho_ssl_ctx *r_ctx, bool verify)
{
    SSL_CTX *ctx = r_ctx->ctx;
    int flags = 0;

    if (verify) {
        if (r_ctx->mode == RHO_SSL_MODE_SERVER)
            flags = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        else if (r_ctx->mode == RHO_SSL_MODE_CLIENT)
            flags = SSL_VERIFY_PEER;
        else
            rho_die("unknown mode (%d)", r_ctx->mode);
    } else {
        flags = SSL_VERIFY_NONE;
    }

    SSL_CTX_set_verify(ctx, flags, NULL);
}

/*
 * params should be freeable after this call; that is, rho_ssl_ctx
 * should copy any data it needs from the params.
 */
struct rho_ssl_ctx *
rho_ssl_ctx_create(struct rho_ssl_params *params)
{
    struct rho_ssl_ctx *r_ctx = NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;

    r_ctx = rhoL_zalloc(sizeof(*r_ctx));

    if (!params->mode)
        rho_die("SSL mode must be specified");
    r_ctx->mode = params->mode;

    if (!params->protocol) 
        rho_die("SSL protocol must be specified");
    method = rho_ssl_protocol2method(params->protocol);
    if (method == NULL)
        rho_openssl_die("unknown protocol '%d'", params->protocol);

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
        rho_openssl_die("SSL context creation failed");

    if (!SSL_CTX_set_cipher_list(ctx, RHO_SSL_CIPHERS_DEFAULT))
        rho_openssl_die("Error setting cipher list '%s'", RHO_SSL_CIPHERS_DEFAULT);

    r_ctx->ctx = ctx;

    if ((params->key_file && !params->cert_file) ||
            (!params->key_file && params->cert_file))
        rho_die("key and cert must either both be speicifed, or both NULL");

    if (params->key_file != NULL || params->cert_file != NULL)
        rho_ssl_ctx_set_key_and_cert_files(r_ctx, params->key_file,
                params->cert_file);

    if (params->ca_file != NULL)
        rho_ssl_ctx_set_ca_file(r_ctx, params->ca_file);

    rho_ssl_ctx_set_verify(r_ctx, params->verify);

    return (r_ctx);
}

void
rho_ssl_ctx_destroy(struct rho_ssl_ctx *r_ctx)
{
    SSL_CTX_free(r_ctx->ctx);
    rhoL_free(r_ctx);
}

static struct rho_ssl *
rho_ssl_create(struct rho_ssl_ctx *r_ctx)
{
    struct rho_ssl *r_ssl = NULL;
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;

    RHO_ASSERT(r_ctx != NULL);
    ctx = r_ctx->ctx;

    r_ssl = rhoL_zalloc(sizeof(*r_ssl));

    ssl = SSL_new(ctx); 
    if (ssl == NULL)
        rho_openssl_die("SSL_new failed");
    
    /* XXX: SSL_set_mode ? */

    if (r_ctx->mode == RHO_SSL_MODE_SERVER)
        SSL_set_accept_state(ssl);
    else
        SSL_set_connect_state(ssl);

    r_ssl->state = RHO_SSL_STATE_NEW;
    r_ssl->ssl = ssl;

    return (r_ssl);
}

static void
rho_ssl_destroy(struct rho_ssl *r_ssl)
{
    SSL_free(r_ssl->ssl);
    rhoL_free(r_ssl);
}

/*
 * SSL WRAPPED SOCKET
 */

static ssize_t
rho_ssl_sock_recv(struct rho_sock *sock, void *buf, size_t len)
{
    int err = 0;
    int sslerr = 0;
    ssize_t n = 0;
    struct rho_ssl *r_ssl = NULL;
    SSL *ssl = NULL;

    RHO_ASSERT(sock != NULL);
    r_ssl = sock->ssl;
    RHO_ASSERT(r_ssl != NULL);
    ssl = r_ssl->ssl;
    RHO_ASSERT(ssl != NULL);
    rho_debug("r_ssl->state = %d\n", r_ssl->state);
    RHO_ASSERT(r_ssl->state == RHO_SSL_STATE_CONNECTED);

    RHO_TRACE_ENTER("sock->fd=%d, len=%zu", sock->fd, len);

    ERR_clear_error();
    err = SSL_read(ssl, buf, (int)len);
    if (err > 0) {
        n = err;
        goto done;
    }

    sslerr = SSL_get_error(ssl, err);
    switch (sslerr) {
    case SSL_ERROR_ZERO_RETURN:
        rho_warn("SSL_read: SSL_ERROR_ZERO_RETURN");
        n = 0;
        break;
    case SSL_ERROR_WANT_READ:
        rho_warn("SSL_read: SSL_WANT_READ");
        n = -1;
        errno = EAGAIN;
        break;
    case SSL_ERROR_WANT_WRITE:
        rho_warn("SSL_read: SSL_WANT_WRITE");
        n = -1;
        errno = EAGAIN;
        break;
    case SSL_ERROR_SYSCALL:
        rho_warn("SSL_read: SSL_ERROR_SYSCALL");
        n = -1;
        r_ssl->state = RHO_SSL_STATE_CLOSED;
        break;
    default:
        n = -1;
        rho_openssl_warn("SSL_read: SSL_ERROR %d", sslerr);
    }

done:
    RHO_TRACE_EXIT("ret=%zd", n);
    return (n);
}

static ssize_t
rho_ssl_sock_send(struct rho_sock *sock, const void *buf, size_t len)
{
    int err = 0;
    int sslerr = 0;
    ssize_t n = 0;
    struct rho_ssl *r_ssl = NULL;
    SSL *ssl = NULL;

    RHO_ASSERT(sock != NULL);
    r_ssl = sock->ssl;
    RHO_ASSERT(r_ssl != NULL);
    ssl = r_ssl->ssl;
    RHO_ASSERT(ssl != NULL);
    RHO_ASSERT(r_ssl->state == RHO_SSL_STATE_CONNECTED);

    RHO_TRACE_ENTER("sock->fd=%d, len=%zu", sock->fd, len);

    ERR_clear_error();
    err = SSL_write(ssl, buf, len);
    if (err > 0) {
        n = err;
        goto done;
    }

    sslerr = SSL_get_error(ssl, err);
    switch (sslerr) {
    case SSL_ERROR_WANT_READ:
        rho_debug("SSL_write: SSL_ERROR_WANT_READ");
        n = -1;
        errno = EAGAIN;
        break;
    case SSL_ERROR_WANT_WRITE:
        rho_debug("SSL_write: SSL_ERROR_WANT_READ");
        n = -1;
        errno = EAGAIN;
        break;
    case SSL_ERROR_SYSCALL:
        rho_debug("SSL_write: SSL_ERROR_SYSCALL");
        n = -1;
        r_ssl->state = RHO_SSL_STATE_CLOSED;
        break;
    default:
        n = -1;
        rho_openssl_warn("write: SSL_ERROR %d", sslerr);
    }

done:
    RHO_TRACE_EXIT("ret=%zd", n);
    return (n);
}

static void
rho_ssl_sock_destroy(struct rho_sock *sock)
{
    struct rho_ssl *r_ssl = NULL;
    SSL *ssl = NULL;

    RHO_ASSERT(sock != NULL);
    r_ssl = sock->ssl;
    RHO_ASSERT(r_ssl != NULL);
    ssl = r_ssl->ssl;
    RHO_ASSERT(ssl != NULL);

    RHO_TRACE_ENTER("sock->fd=%d", sock->fd);

    if (r_ssl->state  == RHO_SSL_STATE_CONNECTED) {
        rho_sock_setblocking(sock);
        (void)SSL_shutdown(ssl);
    }

    rho_ssl_destroy(r_ssl);
    if (sock->fd > 0)
        rhoL_close(sock->fd);
    rhoL_free(sock);

    RHO_TRACE_EXIT();
}

void
rho_ssl_wrap(struct rho_sock *sock, struct rho_ssl_ctx *r_ctx)
{
    struct rho_ssl *r_ssl = NULL;

    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(r_ctx != NULL);

    RHO_TRACE_ENTER("sock->fd=%d", sock->fd);

    r_ssl = rho_ssl_create(r_ctx);
    SSL_set_fd(r_ssl->ssl, sock->fd);
    sock->ssl = r_ssl;
    sock->ops = &rho_ssl_sock_ops;

    RHO_TRACE_EXIT();
    return;
}

/* 
 * return: 
 *   0 on successful handshake, 
 *   1 on SSL_WANT_READ 
 *   2 on SSL_WANT_WRITE
 *  -1 on unrecoverable error
 */
int
rho_ssl_do_handshake(struct rho_sock *sock)
{
    int ret = 0;
    int err = 0;
    int sslerr = 0;
    struct rho_ssl *r_ssl = NULL;
    SSL *ssl = NULL;

    RHO_ASSERT(sock != NULL);
    r_ssl = sock->ssl;
    RHO_ASSERT(r_ssl != NULL);
    ssl = r_ssl->ssl;
    RHO_ASSERT(ssl != NULL);

    RHO_TRACE_ENTER("sock->fd=%d", sock->fd);

    ERR_clear_error();
    err = SSL_do_handshake(ssl);
    sslerr = SSL_get_error(ssl, err);
    switch (sslerr) {
    case SSL_ERROR_NONE:
        r_ssl->state = RHO_SSL_STATE_CONNECTED;
        rho_debug("using SSL protocol: \"%s\", and cipher \"%s\"",
                SSL_get_version(ssl), SSL_get_cipher(ssl));
        ret = 0;
        break;
    case SSL_ERROR_WANT_READ:
        rho_debug("SSL_ERROR_WANT_READ");
        r_ssl->state = RHO_SSL_STATE_CONNECTING;
        ret = 1;
        break;
    case SSL_ERROR_WANT_WRITE:
        rho_debug("SSL_ERROR_WANT_WRITE");
        r_ssl->state = RHO_SSL_STATE_CONNECTING;
        ret = 2;
        break;
    case SSL_ERROR_SYSCALL:
        rho_debug("SSL_ERROR_SYSCALL");
        ret = -1;
        break;
    default:
        rho_openssl_warn("do_handshake: SSL_ERROR %d", sslerr);
        ret = -1;
    }

    return (ret);
}
