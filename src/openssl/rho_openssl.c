#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "rho_mem.h"
#include "rho_thread.h"

#include "openssl/rho_openssl.h"

struct CRYPTO_dynlock_value {
    pthread_mutex_t mutex;
};

/*
 * PROTOTYPES
 */

static void rho_openssl_clear_ssl_queue(void);

/*
 * GLOBALS
 */

static bool rho_openssl_inited = false;
static pthread_mutex_t *rho_openssl_mutexes = NULL;


/*
 * LOCKING
 */

#if OPENSSL_API_COMPAT >= 0x10000000L
static unsigned long
rho_openssl_thread_id_callback(void)
{
    return ((unsigned long)pthread_self());
}

static void
rho_openssl_locking_callback(int mode, int id, const char *file, int line)
{
    (void)file;
    (void)line;

    if (mode & CRYPTO_LOCK)
        rhoL_pthread_mutex_lock(&rho_openssl_mutexes[id]);
    else
        rhoL_pthread_mutex_unlock(&rho_openssl_mutexes[id]);
}
#endif

static void
rho_openssl_init_static_allocated_locking(void)
{
    int i = 0;
    int n = 0;

    n = CRYPTO_num_locks();
    rho_openssl_mutexes = rhoL_mallocarray(n, sizeof(pthread_mutex_t),
            RHO_MEM_ZERO);
    for (i = 0; i < n; i++)
        rhoL_pthread_mutex_init(&rho_openssl_mutexes[i], NULL);

#if OPENSSL_API_COMPAT >= 0x10000000L
    CRYPTO_set_id_callback(rho_openssl_thread_id_callback);
    CRYPTO_set_locking_callback(rho_openssl_locking_callback);
#endif
}

#if OPENSSL_API_COMPAT >= 0x10100000L
static struct CRYPTO_dynlock_value *
rho_openssl_dynlock_create_callback(const char *file, int line)
{
    struct CRYPTO_dynlock_value *value = NULL; 

    (void)file;
    (void)line;

    value = rhoL_zalloc(sizeof(*value));
    rhoL_pthread_mutex_init(&value->mutex, NULL);

    return (value);
}

static void
rho_openssl_dynlock_destroy_callback(struct CRYPTO_dynlock_value *lock,
        const char *file, int line)
{
    (void)file;
    (void)line;

    rhoL_pthread_mutex_destroy(&lock->mutex);
    rhoL_free(lock);
}

static void
rho_openssl_dynlock_lock_callback(int mode, struct CRYPTO_dynlock_value *lock,
        const char *file, int line)
{
    (void)file;
    (void)line;

    if (mode & CRYPTO_LOCK)
        rhoL_pthread_mutex_lock(&lock->mutex);
    else
        rhoL_pthread_mutex_unlock(&lock->mutex);
}
#endif

static void
rho_openssl_init_dynamic_allocated_locking(void)
{
#if OPENSSL_API_COMPAT >= 0x10100000L
    CRYPTO_set_dynlock_create_callback(rho_openssl_dynlock_create_callback); 
    CRYPTO_set_dynlock_destroy_callback(rho_openssl_dynlock_destroy_callback); 
    CRYPTO_set_dynlock_lock_callback(rho_openssl_dynlock_lock_callback); 
#endif
}

/*
 * INIT/FINI
 *
 * TODO: init/fini really need mutexes or atomic updates
 */

/* 
 * see https://wiki.openssl.org/index.php/Library_Initialization
 */
void
rho_ssl_init(void)
{
    if (!rho_openssl_inited) {
        SSL_library_init(); /* same as OpenSSL_add_all_algorithms */
        SSL_load_error_strings();
        rho_openssl_init_static_allocated_locking();
        rho_openssl_init_dynamic_allocated_locking();
        rho_openssl_inited = true;
    }
}

/* 
 * see https://wiki.openssl.org/index.php/Library_Initialization#cleanup
 */
void
rho_ssl_fini(void)
{
    if (rho_openssl_inited) {
        FIPS_mode_set(0);
        ENGINE_cleanup();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_remove_thread_state(NULL);
        ERR_free_strings();
        rhoL_free(rho_openssl_mutexes);
        rho_openssl_inited = false;
    }
}

/*
 * ERROR CHECKING/REPORTING
 */

/* print the contents of the SSL error queue */
static void
rho_openssl_clear_ssl_queue(void)
{
    unsigned long sslcode = ERR_get_error();

    do {
        static const char sslfmt[] = "SSL Error: %s:%s:%s\n";
        fprintf(stderr, sslfmt,
                ERR_lib_error_string(sslcode),
                ERR_func_error_string(sslcode),
                ERR_reason_error_string(sslcode));
    } while ((sslcode = ERR_get_error()) != 0);
}

void
rho_openssl_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);

    rho_openssl_clear_ssl_queue();
}

void
rho_openssl_die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);

    rho_openssl_clear_ssl_queue();
    exit(EXIT_FAILURE);
}
