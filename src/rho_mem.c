#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rho_log.h"
#include "rho_mem.h"

void *
rhoL_malloc(size_t size)
{
    void *p = NULL;

    p = malloc(size);
    if (p == NULL)
        rho_die("out of memory");
    return (p);
}

void *
rhoL_calloc(size_t nmemb, size_t size)
{
    void *p = NULL;

    p = calloc(nmemb, size);
    if (p == NULL)
        rho_die("out of memory");
    return (p);
}

char *
rhoL_strdup(const char *s)
{
    void *p = NULL;

    RHO_ASSERT(s != NULL);

    p = strdup(s);
    if (p == NULL)
        rho_die("out of memory");

    return (p);
}

void *
rhoL_memdup(const void *p, size_t n)
{
    void *out = NULL;

    out = rhoL_malloc(n);
    memcpy(out, p, n);
    return (out);
}

char *
rhoL_strndup(const char *s, size_t n)
{
    void *p = NULL;

    RHO_ASSERT(s != NULL);

    p = strndup(s, n);
    if (p == NULL)
        rho_die("out of memory");

    return (p);
}

void *
rhoL_realloc(void *ptr, size_t size)
{
    void *p = NULL;

    p = realloc(ptr, size);
    if (!p)
        rho_die("out of memory");

    return (p);
}

void
rhoL_free(void *p)
{
    if (p != NULL)
        free(p);
}

#define MUL_NO_OVERFLOW (1UL << (sizeof(size_t) * 4))

/* based on OpenBSD */
void *
rhoL_mallocarray(size_t nmemb, size_t size, int flags)
{
    void *p = NULL;
    size_t n = 0;

    /* 
     * MUL_NO_OVERFLOW * MUL_NO_OVERLOFOW would overflow.
     *
     * So, if both nmemb and size are less then MUL_NO_OVERFLOW
     * we are safe.  However, if at least one is greater, then we
     * see if nmemb * size > SIZE_MAX (we have to also check
     * that nmemb is not zero to avoid a divide-by-zero error.
     */

    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        (nmemb > 0) && ((SIZE_MAX / nmemb) < size)) {
        rho_die("unsigned integer overflow (nmemb=%zu, size%zu)",
                nmemb, size);
    }

    n = nmemb * size;
    p = rhoL_malloc(n);
    if (flags & RHO_MEM_ZERO)
        rho_memzero(p, n);

    return (p);
}

void *
rhoL_reallocarray(void *ptr, size_t nmemb, size_t size, int flags)
{
    void *p = NULL;
    size_t n = 0;

    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        (nmemb > 0) && ((SIZE_MAX / nmemb) < size)) {
        rho_die("unsigned integer overflow (nmemb=%zu, size%zu)",
                nmemb, size);
    }

    n = nmemb * size;
    p = rhoL_realloc(ptr, n);

    if (flags & RHO_MEM_ZERO)
        rho_memzero(p, n);

    return (p);
}
