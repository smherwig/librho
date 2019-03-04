#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>

#include "rho_crypto.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_ssl.h"

#include "openssl/rho_openssl.h"

/*
 * COMPATIBILITY (add openssl 1.1.0 functions to openssl 1.0.2)
 * taken from:
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Compatibility_Layer
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void * OPENSSL_zalloc(size_t num);

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);
const unsigned char * EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
unsigned char * EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);

EVP_MD_CTX * EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);

HMAC_CTX * HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_CTX_reset(HMAC_CTX *ctx);

static void *
OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL)
        memset(ret, 0, num);
    return (ret);
}

int
EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)
{
    return (EVP_CIPHER_CTX_cleanup(ctx));
}

const unsigned char *
EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    return (ctx->iv);
}

unsigned char *
EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    return (ctx->iv);
}

EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
    return (OPENSSL_zalloc(sizeof(EVP_MD_CTX)));
}

void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

int
EVP_MD_CTX_reset(EVP_MD_CTX *ctx)
{
    return (EVP_MD_CTX_cleanup(ctx));
}

HMAC_CTX *
HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        if (!HMAC_CTX_reset(ctx)) {
            HMAC_CTX_free(ctx);
            return (NULL);
        }
    }
    return (ctx);
}

void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (ctx != NULL) {
        HMAC_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

int
HMAC_CTX_reset(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    return (1);
}
#endif /* OPENSSL_VERSION_NUMBER */

/*
 * MESSAGE DIGESTS
 */

struct rho_md {
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    uint8_t *salt;
    size_t saltlen;
};

static const EVP_MD *
rho_md_type2method(enum rho_md_type type)
{
    switch (type) {
    case RHO_MD_MD5:    return EVP_md5();
    case RHO_MD_SHA1:   return EVP_sha1();
    case RHO_MD_SHA224: return EVP_sha224();
    case RHO_MD_SHA256: return EVP_sha256();
    case RHO_MD_SHA384: return EVP_sha384();
    case RHO_MD_SHA512: return EVP_sha512();
    default: rho_die("'%d' is not a valid rho_md_type", type);
    }
}

static void
rho_md_setsalt(struct rho_md *h, void *salt, size_t saltlen)
{
    RHO_ASSERT(h != NULL);
    RHO_ASSERT(salt != NULL);

    if (h->salt != NULL)
        rhoL_free(salt);

    h->salt = rhoL_memdup(salt, saltlen);
    h->saltlen = saltlen;
}

struct rho_md *
rho_md_create(enum rho_md_type md_type, void *salt, size_t saltlen)
{
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    struct rho_md *h = NULL;

    h = rhoL_zalloc(sizeof(*h));

    ctx = EVP_MD_CTX_create();
    if (ctx == NULL)
        rho_openssl_die("EVP_MD_CTX_create failed");

    md = rho_md_type2method(md_type);

    if (1 != EVP_DigestInit_ex(ctx, md, NULL /* engine */))
        rho_openssl_die("EVP_DigestInit_ex failed");

    h->ctx = ctx;
    h->md = md;

    if ((salt != NULL) && (saltlen > 0)) {
        if (1 != EVP_DigestUpdate(ctx, salt, saltlen))
            rho_openssl_die("EVP_DigestUpdate failed\n");
        rho_md_setsalt(h, salt, saltlen);
    }

    return (h); 
}

void 
rho_md_destroy(struct rho_md *h)
{
    EVP_MD_CTX_destroy(h->ctx);
    if (h->salt != NULL)
        rhoL_free(h->salt);
    rhoL_free(h);
}

void
rho_md_update(struct rho_md *h, const void *data, size_t count)
{
    if (1 != EVP_DigestUpdate(h->ctx, data, count))
        rho_openssl_die("EVP_DigestUpdate failed");
}

void rho_md_finish(struct rho_md *h, void *out)
{
    if (1 != EVP_DigestFinal_ex(h->ctx, out, NULL))
        rho_openssl_die("EVP_DigestFinal_ex failed");
}

void
rho_md_reset(struct rho_md *h, void *salt, size_t saltlen)
{
    if (1 != EVP_MD_CTX_reset(h->ctx))
        rho_openssl_die("EVP_MD_CTX_reset failed");

    if (1 != EVP_DigestInit_ex(h->ctx, h->md, NULL /* engine */))
        rho_openssl_die("EVP_DigestInit_ex failed");

    if ((salt != NULL) && (saltlen > 0))
        rho_md_setsalt(h, salt, saltlen);

    if (h->saltlen > 0) {
        if (1 != EVP_DigestUpdate(h->ctx, h->salt, h->saltlen))
            rho_openssl_die("EVP_DigestUpdate failed\n");
    }
}

void
rho_md_oneshot(enum rho_md_type md_type, void *salt, size_t saltlen,
        void *data, size_t count, void *out)
{
    struct rho_md *h = NULL;

    h = rho_md_create(md_type, salt, saltlen);
    rho_md_update(h, data, count);
    rho_md_finish(h, out);
    rho_md_destroy(h);
}

/*
 * HMAC
 */

struct rho_hmac {
    HMAC_CTX *ctx;
    const EVP_MD *md;
    uint8_t *key;
    size_t  keylen;
};

static void
rho_hmac_setkey(struct rho_hmac *hm, const void *key, size_t keylen)
{
    RHO_ASSERT(hm != NULL);
    RHO_ASSERT(key != NULL);

    if (hm->key != NULL)
        rhoL_free(hm->key);
    hm->key = rhoL_memdup(key, keylen);
    hm->keylen = keylen;
}

struct rho_hmac *
rho_hmac_create(enum rho_md_type md_type, const void *key, size_t keylen)
{
    struct rho_hmac *hm = NULL;
    HMAC_CTX *ctx = NULL;
    const EVP_MD *md = NULL;

    hm = rhoL_zalloc(sizeof(*hm));

    ctx = HMAC_CTX_new();
    if (ctx == NULL)
        rho_openssl_die("HMAC_CTX_new failed");
    
    md = rho_md_type2method(md_type);
    if (1 != HMAC_Init_ex(ctx, key, keylen, md, NULL /* engine */))
        rho_openssl_die("HMAC_Init_ex failed");

    hm->ctx = ctx; 
    hm->md = md;
    rho_hmac_setkey(hm, key, keylen);

    return (hm);
}

void
rho_hmac_destroy(struct rho_hmac *hm)
{
    HMAC_CTX_free(hm->ctx);
    rhoL_free(hm->key);
    rhoL_free(hm);
}

void
rho_hmac_update(struct rho_hmac *hm, const void *data, size_t len)
{
    /* TODO: check overflow in len param */
    if (1 != HMAC_Update(hm->ctx, data, (int)len))
        rho_openssl_die("HMAC_Update failed");
}

void
rho_hmac_finish(struct rho_hmac *hm, void *md)
{
    unsigned int len = 0;

    if (1 != HMAC_Final(hm->ctx, md, &len))
        rho_openssl_die("HMAC_Final failed");
}

void
rho_hmac_reset(struct rho_hmac *hm, void *key, size_t keylen)
{
    if (1 != HMAC_CTX_reset(hm->ctx))
        rho_openssl_die("HMAC_CTX_reset failed");

    if (key != NULL)
        rho_hmac_setkey(hm, key, keylen);

    if (1 != HMAC_Init_ex(hm->ctx, hm->key, hm->keylen, hm->md, NULL))
        rho_openssl_die("HMAC_Init_ex failed");
}

void
rho_hmac_oneshot(enum rho_md_type md_type, void *key, size_t keylen,
        void *data, size_t datalen, void *out)
{
    struct rho_hmac *hm = NULL;

    hm = rho_hmac_create(md_type, key, keylen);
    rho_hmac_update(hm, data, datalen);
    rho_hmac_finish(hm, out);
    rho_hmac_destroy(hm);
}

/*
 * KEY-DERIVATION FUNCTIONS (KDFs)
 */

void
rho_kdf_pbkdf2hmac(const char *pass, uint8_t *salt, size_t saltlen,
        int iterations, struct rho_md *h, uint8_t *key, size_t keylen)
{
    size_t passlen = 0;
    
    RHO_ASSERT(h != NULL);
    RHO_ASSERT(h->md != NULL);

    passlen = strlen(pass);

    if (1 != PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations,
            h->md, keylen, key))
        rho_openssl_die("PKCS5_PBKDF2_HMAC failed");
}

void
rho_kdf_pbkdf2hmac_oneshot(const char *pass, uint8_t *salt, size_t saltlen,
        int iterations, enum rho_md_type md_type, uint8_t *key, size_t keylen)
{
    size_t passlen = 0;
    struct rho_md *h = NULL;
    
    passlen = strlen(pass);
    h = rho_md_create(md_type, salt, saltlen);

    if (1 != PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations,
            h->md, keylen, key))
        rho_openssl_die("PKCS5_PBKDF2_HMAC failed");

    rho_md_destroy(h);
}

/*
 * CIPHERS
 */

struct rho_cipher {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    enum rho_cipher_type type; 
    enum rho_cipher_mode mode;
    uint8_t *key;
    uint8_t *iv;
};

static const EVP_CIPHER *
rho_cipher_type2method(enum rho_cipher_type type)
{
    switch (type) {
    case RHO_CIPHER_AES_128_CBC: return EVP_aes_128_cbc();
    case RHO_CIPHER_AES_128_ECB: return EVP_aes_128_ecb();

    case RHO_CIPHER_AES_192_CBC: return EVP_aes_192_cbc();
    case RHO_CIPHER_AES_192_ECB: return EVP_aes_192_ecb();

    case RHO_CIPHER_AES_256_CBC: return EVP_aes_256_cbc();
    case RHO_CIPHER_AES_256_ECB: return EVP_aes_256_ecb();
    case RHO_RIPHER_AES_256_XTS: return EVP_aes_256_xts();

    default: rho_die("'%d' is not a valid rho_cipher_type", type);
    }
}

static void
rho_cipher_setkey(struct rho_cipher *c, const void *key)
{
    int keylen = 0;

    RHO_ASSERT(c != NULL);
    RHO_ASSERT(c->cipher != NULL);

    keylen = EVP_CIPHER_key_length(c->cipher);

    if (c->key != NULL)
        rhoL_free(c->key);
    c->key = rhoL_memdup(key, keylen);
}

static void
rho_cipher_setiv(struct rho_cipher *c, const void *iv)
{
    int ivlen = 0;

    RHO_ASSERT(c != NULL);
    RHO_ASSERT(c->cipher != NULL);

    ivlen = EVP_CIPHER_iv_length(c->cipher);

    if (c->iv != NULL)
        rhoL_free(c->iv);
    c->iv = rhoL_memdup(iv, ivlen);
}

/* mode is encryption or decryption */
struct rho_cipher *
rho_cipher_create(enum rho_cipher_type type, enum rho_cipher_mode mode,
        bool padded, const void *key, const void *iv)
{
    struct rho_cipher *c = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int enc = mode == RHO_CIPHER_MODE_ENCRYPT ? 1 : 0;

    c = rhoL_zalloc(sizeof(*c));

    ctx = EVP_CIPHER_CTX_new(); 
    if (ctx == NULL)
        rho_openssl_die("EVP_CIPHER_CTX_new failed");

    cipher = rho_cipher_type2method(type);
    if (1 != EVP_CipherInit_ex(ctx, cipher, NULL /* impl */, key, iv, enc))
        rho_openssl_die("EVP_CipherInit_ex failed");

    (void)EVP_CIPHER_CTX_set_padding(ctx, padded);

    c->ctx = ctx;
    c->cipher = cipher;
    c->type = type;
    c->mode = mode;

    if (key != NULL)
        rho_cipher_setkey(c, key);

    if (iv != NULL)
        rho_cipher_setiv(c, iv);

    return (c);
}

void
rho_cipher_destroy(struct rho_cipher *c)
{
    EVP_CIPHER_CTX_free(c->ctx);
    if (c->key != NULL)
        rhoL_free(c->key);
    if (c->iv != NULL)
        rhoL_free(c->iv);
    rhoL_free(c);
}

void
rho_cipher_update(struct rho_cipher *c, const void *in, size_t inlen, void *out,
        size_t *outlen)
{
    /* XXX: inlen can only be an int -- check for overflow */
    if (1 != EVP_CipherUpdate(c->ctx, out, (int *)outlen, in, (int)inlen))
        rho_openssl_die("EVP_CipherUpdate failed");
}

void
rho_cipher_finish(struct rho_cipher *c, void *out, size_t *outlen)
{
    if (1 != EVP_CipherFinal_ex(c->ctx, out, (int *)outlen))
        rho_openssl_die("EVP_CipherFinal_ex failed");
}

void
rho_cipher_reset(struct rho_cipher *c, enum rho_cipher_mode mode, 
        bool padded, void *key, void *iv)
{
    int enc = mode == RHO_CIPHER_MODE_ENCRYPT ? 1 : 0;
    if (1 != EVP_CIPHER_CTX_reset(c->ctx))
        rho_openssl_die("EVP_CIPHER_CTX_reset failed");

    if (key != NULL)
        rho_cipher_setkey(c, key);
    if (iv != NULL)
        rho_cipher_setiv(c, iv);

    if (1 != EVP_CipherInit_ex(c->ctx, c->cipher, NULL /* impl */, c->key, c->iv, enc))
        rho_openssl_die("EVP_CipherInit_ex failed");

    (void)EVP_CIPHER_CTX_set_padding(c->ctx, padded);
}

void
rho_cipher_oneshot(enum rho_cipher_type type, enum rho_cipher_mode mode,
        bool padded, const void *key, const void *iv, const void *in,
        size_t inlen, void *out, size_t *outlen)
{
    struct rho_cipher *c = NULL;
    size_t len = 0;

    c = rho_cipher_create(type, mode, padded, key, iv);
    rho_cipher_update(c, in, inlen, out, &len); 
    *outlen += len;
    rho_cipher_finish(c, out + len, &len);
    *outlen += len;
    rho_cipher_destroy(c);
}
