#include <stddef.h>

#include <bearssl.h>

#include "rho_fd.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_ssl.h"
#include "rho_sock.h"
#include "rho_vector.h"

#include "bearssl/rho_bearssl_cert.h"
#include "bearssl/rho_bearssl_common.h"
#include "bearssl/rho_bearssl_error.h"
#include "bearssl/rho_bearssl_key.h"
#include "bearssl/rho_bearssl_pem.h"
#include "bearssl/rho_bearssl_ta.h"
/*
 * Type for a known hash function.
 */
typedef struct {
	const char *name;
	const br_hash_class *hclass;
	const char *comment;
} rho_ssl_hash_function;


/**********************************************************
 * FUNCTION PROTOTYPES
 **********************************************************/
static const unsigned char * rho_ssl_get_hash_oid(int id);
static const br_hash_class * rho_ssl_get_hash_impl(int hash_id);

static const char * rho_ssl_ec_curve_name(int curve);

/* for client certificates */
static void rho_ssl_cc_start_name_list(
        const br_ssl_client_certificate_class **pctx);

static void rho_ssl_cc_start_name(const br_ssl_client_certificate_class **pctx,
        size_t len);

static void rho_ssl_cc_append_name(const br_ssl_client_certificate_class **pctx,
	const unsigned char *data, size_t len);

static void rho_ssl_cc_end_name(const br_ssl_client_certificate_class **pctx);

static void rho_ssl_cc_end_name_list(
        const br_ssl_client_certificate_class **pctx);

static const char * rho_ssl_hash_function_name(int id);

static void rho_ssl_print_hashes(unsigned hh, unsigned hh2);
static int rho_ssl_choose_hash(unsigned hh);

static void rho_ssl_cc_choose(const br_ssl_client_certificate_class **pctx,
	const br_ssl_client_context *cc, uint32_t auth_types,
	br_ssl_client_certificate *choices);

static uint32_t rho_ssl_cc_do_keyx(const br_ssl_client_certificate_class **pctx,
	unsigned char *data, size_t *len);

static size_t rho_ssl_cc_do_sign(const br_ssl_client_certificate_class **pctx,
	int hash_id, size_t hv_len, unsigned char *data, size_t len);

/* for wrapped socket */
static ssize_t rho_ssl_sock_recv(struct rho_sock *sock, void *buf,
        size_t len);
static ssize_t rho_ssl_sock_send(struct rho_sock *sock, const void *buf, 
        size_t len);
static void rho_ssl_sock_destroy(struct rho_sock *sock);

/**********************************************************
 * GLOBALS
 **********************************************************/

static const br_ssl_client_certificate_class rho_ssl_ccert_vtable = {
	sizeof(struct rho_ssl_ccert_context),
	rho_ssl_cc_start_name_list,
	rho_ssl_cc_start_name,
	rho_ssl_cc_append_name,
	rho_ssl_cc_end_name,
	rho_ssl_cc_end_name_list,
	rho_ssl_cc_choose,
	rho_ssl_cc_do_keyx,
	rho_ssl_cc_do_sign
};

static struct rho_sock_ops rho_ssl_sock_ops = {
    .recv = rho_ssl_sock_recv,
    .send = rho_ssl_sock_send,
    .destroy = rho_ssl_sock_destroy,
};

/*
 * OID for hash functions in RSA signatures.
 */
static const unsigned char RHO_SSL_HASH_OID_SHA1[] = {
	0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A
};

static const unsigned char RHO_SSL_HASH_OID_SHA224[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
};

static const unsigned char RHO_SSL_HASH_OID_SHA256[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};

static const unsigned char RHO_SSL_HASH_OID_SHA384[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};

static const unsigned char RHO_SSL_HASH_OID_SHA512[] = {
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

static const unsigned char *RHO_SSL_HASH_OID[] = {
	RHO_SSL_HASH_OID_SHA1,
	RHO_SSL_HASH_OID_SHA224,
	RHO_SSL_HASH_OID_SHA256,
	RHO_SSL_HASH_OID_SHA384,
	RHO_SSL_HASH_OID_SHA512
};

/*
 * Known hash functions. Last element has a NULL name.
 */
const rho_ssl_hash_function rho_ssl_hash_functions[] = {
	{ "md5",     &br_md5_vtable,     "MD5" },
	{ "sha1",    &br_sha1_vtable,    "SHA-1" },
	{ "sha224",  &br_sha224_vtable,  "SHA-224" },
	{ "sha256",  &br_sha256_vtable,  "SHA-256" },
	{ "sha384",  &br_sha384_vtable,  "SHA-384" },
	{ "sha512",  &br_sha512_vtable,  "SHA-512" },
	{ NULL, 0, NULL }
};

/**********************************************************
 * STATIC FUNCTIONS
 **********************************************************/


/*
 * Get the encoded OID for a given hash function (to use with PKCS#1
 * signatures). If the hash function ID is 0 (for MD5+SHA-1), or if
 * the ID is not one of the SHA-* functions (SHA-1, SHA-224, SHA-256,
 * SHA-384, SHA-512), then this function returns NULL.
 */
static const unsigned char *
rho_ssl_get_hash_oid(int id)
{
	if (id >= 2 && id <= 6) {
		return RHO_SSL_HASH_OID[id - 2];
	} else {
		return NULL;
	}
}

/*
 * Get a hash implementation by ID. This returns NULL if the hash
 * implementation is not available.
 */
static const br_hash_class *
rho_ssl_get_hash_impl(int hash_id)
{
	size_t u;

    RHO_TRACE_ENTER();

	if (hash_id == 0) {
		return &br_md5sha1_vtable;
	}
	for (u = 0; rho_ssl_hash_functions[u].name; u ++) {
		const br_hash_class *hc;
		int id;

		hc = rho_ssl_hash_functions[u].hclass;
		id = (hc->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK;
		if (id == hash_id) {
			return hc;
		}
	}
	return NULL;
}

/*
 * Get the symbolic name for an elliptic curve (by ID).
 */
static const char *
rho_ssl_ec_curve_name(int curve)
{
	switch (curve) {
	case BR_EC_sect163k1:        return "sect163k1";
	case BR_EC_sect163r1:        return "sect163r1";
	case BR_EC_sect163r2:        return "sect163r2";
	case BR_EC_sect193r1:        return "sect193r1";
	case BR_EC_sect193r2:        return "sect193r2";
	case BR_EC_sect233k1:        return "sect233k1";
	case BR_EC_sect233r1:        return "sect233r1";
	case BR_EC_sect239k1:        return "sect239k1";
	case BR_EC_sect283k1:        return "sect283k1";
	case BR_EC_sect283r1:        return "sect283r1";
	case BR_EC_sect409k1:        return "sect409k1";
	case BR_EC_sect409r1:        return "sect409r1";
	case BR_EC_sect571k1:        return "sect571k1";
	case BR_EC_sect571r1:        return "sect571r1";
	case BR_EC_secp160k1:        return "secp160k1";
	case BR_EC_secp160r1:        return "secp160r1";
	case BR_EC_secp160r2:        return "secp160r2";
	case BR_EC_secp192k1:        return "secp192k1";
	case BR_EC_secp192r1:        return "secp192r1";
	case BR_EC_secp224k1:        return "secp224k1";
	case BR_EC_secp224r1:        return "secp224r1";
	case BR_EC_secp256k1:        return "secp256k1";
	case BR_EC_secp256r1:        return "secp256r1";
	case BR_EC_secp384r1:        return "secp384r1";
	case BR_EC_secp521r1:        return "secp521r1";
	case BR_EC_brainpoolP256r1:  return "brainpoolP256r1";
	case BR_EC_brainpoolP384r1:  return "brainpoolP384r1";
	case BR_EC_brainpoolP512r1:  return "brainpoolP512r1";
	default:
		return "unknown";
	}
}

/**********************************************************
 * CLIENT CERTIFICATE CLASS / STATE MACHINE
 **********************************************************/ 
static void
rho_ssl_cc_start_name_list(const br_ssl_client_certificate_class **pctx)
{
	struct rho_ssl_ccert_context *zc;

    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	if (zc->verbose) {
		fprintf(stderr, "Server requests a client certificate.\n");
		fprintf(stderr, "--- anchor DN list start ---\n");
	}

    RHO_TRACE_EXIT();
}

static void
rho_ssl_cc_start_name(const br_ssl_client_certificate_class **pctx, size_t len)
{
	struct rho_ssl_ccert_context *zc;
    
    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	if (zc->verbose) {
		fprintf(stderr, "new anchor name, length = %u\n",
			(unsigned)len);
	}

    RHO_TRACE_EXIT();
}

static void
rho_ssl_cc_append_name(const br_ssl_client_certificate_class **pctx,
	const unsigned char *data, size_t len)
{
	struct rho_ssl_ccert_context *zc;

    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	if (zc->verbose) {
		size_t u;

		for (u = 0; u < len; u ++) {
			if (u == 0) {
				fprintf(stderr, "  ");
			} else if (u > 0 && u % 16 == 0) {
				fprintf(stderr, "\n  ");
			}
			fprintf(stderr, " %02x", data[u]);
		}
		if (len > 0) {
			fprintf(stderr, "\n");
		}
	}

    RHO_TRACE_EXIT();
}

static void
rho_ssl_cc_end_name(const br_ssl_client_certificate_class **pctx)
{
    RHO_TRACE_ENTER();
	(void)pctx;
    RHO_TRACE_EXIT();
}

static void
rho_ssl_cc_end_name_list(const br_ssl_client_certificate_class **pctx)
{
	struct rho_ssl_ccert_context *zc;

    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	if (zc->verbose) {
		fprintf(stderr, "--- anchor DN list end ---\n");
	}

    RHO_TRACE_EXIT();
}

/* TODO: move to rho_crypto_bearssl.c */
static const char *
rho_ssl_hash_function_name(int id)
{
    RHO_TRACE_ENTER();

	switch (id) {
	case br_md5sha1_ID:  return "MD5+SHA-1";
	case br_md5_ID:      return "MD5";
	case br_sha1_ID:     return "SHA-1";
	case br_sha224_ID:   return "SHA-224";
	case br_sha256_ID:   return "SHA-256";
	case br_sha384_ID:   return "SHA-384";
	case br_sha512_ID:   return "SHA-512";
	default:
		return "unknown";
	}
}

static void
rho_ssl_print_hashes(unsigned hh, unsigned hh2)
{
	int i;

    RHO_TRACE_ENTER();

	for (i = 0; i < 8; i ++) {
		const char *name;

		name = rho_ssl_hash_function_name(i);
		if (((hh >> i) & 1) != 0) {
			fprintf(stderr, " %s", name);
		} else if (((hh2 >> i) & 1) != 0) {
			fprintf(stderr, " (%s)", name);
		}
	}

    RHO_TRACE_EXIT();
}

static int
rho_ssl_choose_hash(unsigned hh)
{
	static const int f[] = {
		br_sha256_ID, br_sha224_ID, br_sha384_ID, br_sha512_ID,
		br_sha1_ID, br_md5sha1_ID, -1
	};
    size_t u;
    
    RHO_TRACE_ENTER();

	for (u = 0; f[u] >= 0; u ++) {
		if (((hh >> f[u]) & 1) != 0) {
			return f[u];
		}
	}

	return -1;
}

static void
rho_ssl_cc_choose(const br_ssl_client_certificate_class **pctx,
	const br_ssl_client_context *cc, uint32_t auth_types,
	br_ssl_client_certificate *choices)
{
	struct rho_ssl_ccert_context *zc;
	int scurve;

    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	scurve = br_ssl_client_get_server_curve(cc);
	if (zc->verbose) {
		unsigned hashes;

		hashes = br_ssl_client_get_server_hashes(cc);
		if ((auth_types & 0x00FF) != 0) {
			fprintf(stderr, "supported: RSA signatures:");
			rho_ssl_print_hashes(auth_types, hashes);
			fprintf(stderr, "\n");
		}
		if ((auth_types & 0xFF00) != 0) {
			fprintf(stderr, "supported: ECDSA signatures:");
			rho_ssl_print_hashes(auth_types >> 8, hashes >> 8);
			fprintf(stderr, "\n");
		}
		if ((auth_types & 0x010000) != 0) {
			fprintf(stderr, "supported:"
				" fixed ECDH (cert signed with RSA)\n");
		}
		if ((auth_types & 0x020000) != 0) {
			fprintf(stderr, "supported:"
				" fixed ECDH (cert signed with ECDSA)\n");
		}
		if (scurve) {
			fprintf(stderr, "server key curve: %s (%d)\n",
				rho_ssl_ec_curve_name(scurve), scurve);
		} else {
			fprintf(stderr, "server key is not EC\n");
		}
	}
	switch (zc->sk->key_type) {
	case BR_KEYTYPE_RSA:
		if ((choices->hash_id = rho_ssl_choose_hash(auth_types)) >= 0) {
			if (zc->verbose) {
				fprintf(stderr, "using RSA, hash = %d (%s)\n",
					choices->hash_id,
					rho_ssl_hash_function_name(choices->hash_id));
			}
			choices->auth_type = BR_AUTH_RSA;
			choices->chain = zc->chain;
			choices->chain_len = zc->chain_len;
			return;
		}
		break;
	case BR_KEYTYPE_EC:
		if (zc->issuer_key_type != 0
			&& scurve == zc->sk->key.ec.curve)
		{
			int x;

			x = (zc->issuer_key_type == BR_KEYTYPE_RSA) ? 16 : 17;
			if (((auth_types >> x) & 1) != 0) {
				if (zc->verbose) {
					fprintf(stderr, "using static ECDH\n");
				}
				choices->auth_type = BR_AUTH_ECDH;
				choices->hash_id = -1;
				choices->chain = zc->chain;
				choices->chain_len = zc->chain_len;
				return;
			}
		}
		if ((choices->hash_id = rho_ssl_choose_hash(auth_types >> 8)) >= 0) {
			if (zc->verbose) {
				fprintf(stderr, "using ECDSA, hash = %d (%s)\n",
					choices->hash_id,
					rho_ssl_hash_function_name(choices->hash_id));
			}
			choices->auth_type = BR_AUTH_ECDSA;
			choices->chain = zc->chain;
			choices->chain_len = zc->chain_len;
			return;
		}
		break;
	}
	if (zc->verbose) {
		fprintf(stderr, "no matching client certificate\n");
	}
	choices->chain = NULL;
	choices->chain_len = 0;
}

static uint32_t
rho_ssl_cc_do_keyx(const br_ssl_client_certificate_class **pctx,
	unsigned char *data, size_t *len)
{
	const br_ec_impl *iec;
	struct rho_ssl_ccert_context *zc;
	size_t xoff, xlen;
	uint32_t r;

    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	iec = br_ec_get_default();
	r = iec->mul(data, *len, zc->sk->key.ec.x,
		zc->sk->key.ec.xlen, zc->sk->key.ec.curve);
	xoff = iec->xoff(zc->sk->key.ec.curve, &xlen);
	memmove(data, data + xoff, xlen);
	*len = xlen;

    RHO_TRACE_EXIT();

	return r;
}

static size_t
rho_ssl_cc_do_sign(const br_ssl_client_certificate_class **pctx,
	int hash_id, size_t hv_len, unsigned char *data, size_t len)
{
	struct rho_ssl_ccert_context *zc;
	unsigned char hv[64];

    RHO_TRACE_ENTER();

	zc = (struct rho_ssl_ccert_context *)pctx;
	memcpy(hv, data, hv_len);
	switch (zc->sk->key_type) {
		const br_hash_class *hc;
		const unsigned char *hash_oid;
		uint32_t x;
		size_t sig_len;

	case BR_KEYTYPE_RSA:
		hash_oid = rho_ssl_get_hash_oid(hash_id);
		if (hash_oid == NULL && hash_id != 0) {
			if (zc->verbose) {
				fprintf(stderr, "ERROR: cannot RSA-sign with"
					" unknown hash function: %d\n",
					hash_id);
			}
			return 0;
		}
		sig_len = (zc->sk->key.rsa.n_bitlen + 7) >> 3;
		if (len < sig_len) {
			if (zc->verbose) {
				fprintf(stderr, "ERROR: cannot RSA-sign,"
					" buffer is too small"
					" (sig=%lu, buf=%lu)\n",
					(unsigned long)sig_len,
					(unsigned long)len);
			}
			return 0;
		}
		x = br_rsa_pkcs1_sign_get_default()(
			hash_oid, hv, hv_len, &zc->sk->key.rsa, data);
		if (!x) {
			if (zc->verbose) {
				fprintf(stderr, "ERROR: RSA-sign failure\n");
			}
			return 0;
		}
		return sig_len;

	case BR_KEYTYPE_EC:
		hc = rho_ssl_get_hash_impl(hash_id);
		if (hc == NULL) {
			if (zc->verbose) {
				fprintf(stderr, "ERROR: cannot ECDSA-sign with"
					" unknown hash function: %d\n",
					hash_id);
			}
			return 0;
		}
		if (len < 139) {
			if (zc->verbose) {
				fprintf(stderr, "ERROR: cannot ECDSA-sign"
					" (output buffer = %lu)\n",
					(unsigned long)len);
			}
			return 0;
		}
		sig_len = br_ecdsa_sign_asn1_get_default()(
			br_ec_get_default(), hc, hv, &zc->sk->key.ec, data);
		if (sig_len == 0) {
			if (zc->verbose) {
				fprintf(stderr, "ERROR: ECDSA-sign failure\n");
			}
			return 0;
		}
		return sig_len;

	default:
		return 0;
	}
}

static void
rho_ssl_ctx_set_protocol(struct rho_ssl_ctx *sc, enum rho_ssl_protocol protocol)
{
    int version = 0;

    RHO_TRACE_ENTER();

    switch (protocol) {
    case RHO_SSL_PROTOCOL_TLSv1:
        version = BR_TLS10;
        break;
    case RHO_SSL_PROTOCOL_TLSv1_1:
        version = BR_TLS11;
        break;
    case RHO_SSL_PROTOCOL_TLSv1_2:
        version = BR_TLS12;
        break;
    default:
        rho_die("unknown ssl protocol (code=%d)\n", protocol);
    }

    sc->protocol_version = version;
    br_ssl_engine_set_versions(&(sc->cc.eng), version, version);

    RHO_TRACE_EXIT();
}

static void
rho_ssl_ctx_set_key_and_cert_files(struct rho_ssl_ctx *sc, const char *key_path,
        const char *cert_path)
{
    size_t chain_len = 0;
    br_x509_certificate *chain = NULL;
    struct rho_bearssl_key *sk = NULL;

    RHO_TRACE_ENTER();

    /* TODO: error checking */
    sk = rho_bearssl_key_from_file(key_path);
    chain = rho_bearssl_certs_from_file(cert_path, &chain_len);

    sc->zc.vtable = &rho_ssl_ccert_vtable;
    sc->zc.verbose = 1;
    sc->zc.chain = chain;
    sc->zc.chain_len = chain_len;
    sc->zc.sk = sk;
    sc->zc.issuer_key_type = 0; /* XXX: is this right? */
    br_ssl_client_set_client_certificate(&sc->cc, &(sc->zc.vtable));

    RHO_TRACE_EXIT();
}

struct rho_ssl_ctx *
rho_ssl_ctx_create(struct rho_ssl_params *params)
{
    struct rho_ssl_ctx *sc = NULL;
    struct rho_bearssl_ta_list tas = RHO_VECTOR_INIT;
    size_t n = 0;

    RHO_TRACE_ENTER();

    sc = rhoL_zalloc(sizeof(*sc));

    if (!params->mode)
        rho_die("SSL mode must be specified");

    if (!params->protocol)
        rho_die("SSL protocol must be specified");

    if (params->ca_file == NULL)
        rho_die("currently, a CA file must be specified");

    br_ssl_client_zero(&sc->cc);

    fprintf(stderr, "1\n");

    n = rho_bearssl_ta_list_from_file(&tas, params->ca_file);
    if (n == 0)
        rho_die("failed to read any trust anchors from file \"%s\"", params->ca_file);

    fprintf(stderr, "2\n");

    br_ssl_client_init_full(&sc->cc, &sc->xc,
            &RHO_VECTOR_ELT(tas, 0), RHO_VECTOR_LEN(tas));
    /* 
     * the br_x509_minimal ctx just holds  points to the tas, so we can't 
     * free them here.
     */
    fprintf(stderr, "3\n");
    rho_ssl_ctx_set_protocol(sc, params->protocol);
    fprintf(stderr, "4\n");

    if ((params->key_file && !params->cert_file) ||
            (!params->key_file && params->cert_file))
        rho_die("key and cert must either both be speicifed, or both NULL");
    if (params->key_file != NULL || params->cert_file != NULL)
        rho_ssl_ctx_set_key_and_cert_files(sc, params->key_file,
                params->cert_file);
    fprintf(stderr, "5\n");

    sc->rbuf = rhoL_zalloc(BR_SSL_BUFSIZE_INPUT);
    sc->wbuf = rhoL_zalloc(BR_SSL_BUFSIZE_OUTPUT);
    br_ssl_engine_set_buffers_bidi(&(sc->cc.eng), sc->rbuf, BR_SSL_BUFSIZE_INPUT,
            sc->wbuf, BR_SSL_BUFSIZE_OUTPUT);

    fprintf(stderr, "6\n");
    
    RHO_TRACE_EXIT();

    return (sc);
}

void
rho_ssl_ctx_destroy(struct rho_ssl_ctx *ssl_ctx)
{
    struct rho_ssl_ccert_context *zc = &ssl_ctx->zc;
    br_x509_minimal_context *xc = &ssl_ctx->xc;
    size_t  i = 0;
    size_t  num_anchors = 0;

    RHO_TRACE_ENTER();

    /* 
     * deallocate the ccert_context parts 
     */

    if (zc->sk != NULL)
        rho_bearssl_key_destroy(zc->sk);

    if (zc->chain != NULL)
        rho_bearssl_certs_destroy(zc->chain, zc->chain_len);

    /* 
     * deallocate the x509_context parts 
     */

    num_anchors = xc->trust_anchors_num;
    for (i = 0; i < num_anchors; i++) {
        /* unconst */
        rho_bearssl_ta_destroy((br_x509_trust_anchor *)(&xc->trust_anchors[i]));
    }
    if (num_anchors > 0) {
        /* unconst */
        rhoL_free((br_x509_trust_anchor *)xc->trust_anchors);
    }

    /* 
     * deallocate the io buffers
     */
    rhoL_free(ssl_ctx->rbuf);
    rhoL_free(ssl_ctx->wbuf);
    
    rhoL_free(ssl_ctx);

    RHO_TRACE_EXIT();
}

/*
 * SSL WRAPPED SOCKET
 */

static ssize_t
rho_ssl_sock_recv(struct rho_sock *sock, void *buf, size_t len)
{
    struct rho_ssl_ctx *sc = sock->ssl_ctx;
    br_ssl_engine_context *engine =  &(sc->cc.eng);
    int n = 0;

    RHO_TRACE_ENTER("len=%zu", len);

    n = br_sslio_read(&sc->ioc, buf, len);
    if (n == -1)
        rho_bearssl_warn_last_error(engine, "br_sslio_read");

    RHO_TRACE_EXIT("n=%d",n);
    return (n);
}

static ssize_t
rho_ssl_sock_send(struct rho_sock *sock, const void *buf, size_t len)
{
    struct rho_ssl_ctx *sc = sock->ssl_ctx;
    br_ssl_engine_context *engine =  &(sc->cc.eng);
    int n = 0;
    int error = 0;

    RHO_TRACE_ENTER("len=%zu", len);

    n = br_sslio_write(&sc->ioc, buf, len);
    if (n == -1) {
        rho_bearssl_warn_last_error(engine, "br_sslio_write");
        goto done;
    }
    
    error = br_sslio_flush(&sc->ioc);    /* TODO: check errors */
    if (error == -1) {
        rho_bearssl_warn_last_error(engine, "br_sslio_flush");
        n = -1;
        goto done;
    }

done:
    RHO_TRACE_EXIT("n=%d", n);
    return (n);
}

static void
rho_ssl_sock_destroy(struct rho_sock *sock)
{
    int error = 0;
    struct rho_ssl_ctx *sc = sock->ssl_ctx;
    br_sslio_context *ioc = &(sc->ioc);
    br_ssl_engine_context *engine =  &(sc->cc.eng);

    RHO_TRACE_ENTER();

    rho_debug("before br_sslio_flush");

    error = br_sslio_flush(ioc);
    if (error == -1)
        rho_bearssl_warn_last_error(engine, "br_sslio_flush");

    rho_debug("after br_sslio_flush");


#if 0
    /* for some reason, this doesn't work with my python echoserver --
     *  br_sslio_close gets caught in an infinite loop
     */
    rho_debug("before br_sslio_close");

    error = br_sslio_close(ioc);
    if (error == -1)
        rho_bearssl_warn_last_error(engine, "br_sslio_close");

    rho_debug("after br_sslio_close");
#endif

    if (sock->fd > 0)
        rhoL_close(sock->fd);
    
    rhoL_free(sock);

    RHO_TRACE_EXIT();
}

static int
rho_ssl_low_read(void *u, unsigned char *data, size_t len)
{
    struct rho_sock *sock = u;
    ssize_t n = 0;

    RHO_TRACE_ENTER("len=%zu", len);
    n = recv(sock->fd, data, len, 0);
    RHO_TRACE_EXIT("n=%zd", n);

    return ((int)n);
}

static int
rho_ssl_low_write(void *u, const unsigned char *data, size_t len)
{
    struct rho_sock *sock = u;
    ssize_t n = 0;

    RHO_TRACE_ENTER("len=%zu", len);
    n = send(sock->fd, data, len, 0);
    RHO_TRACE_EXIT("n=%zd",n);
    
    return ((int)n);
}

void
rho_ssl_wrap(struct rho_sock *sock, struct rho_ssl_ctx *sc)
{
    RHO_TRACE_ENTER();

    sock->ops = &rho_ssl_sock_ops;
    sock->ssl_ctx = sc;
    br_ssl_client_reset(&sc->cc, NULL, 0);
    br_sslio_init(&sc->ioc, &(sc->cc.eng), rho_ssl_low_read, sock,
            rho_ssl_low_write, sock);

    RHO_TRACE_EXIT();
}

int 
rho_ssl_do_handshake(struct rho_sock *sock)
{
    RHO_TRACE_ENTER();
    (void)sock;
    RHO_TRACE_EXIT();
    return (0);
}
