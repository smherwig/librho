#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "rho_bitmap.h"
#include "rho_log.h"
#include "rho_mem.h"

#define RHO_BITMAP_ELEM_SIZE 4 /* sizeof(uint32_t) */
#define RHO_BITMAP_ELEM_BITS 32

#define RHO_BITMAP_ELEMS(bitlen) \
    (((bitlen) / RHO_BITMAP_ELEM_BITS) + \
     (((bitlen) % RHO_BITMAP_ELEM_BITS) ? 1 : 0))

struct rho_bitmap *
rho_bitmap_create(bool resizeable, size_t bitlen)
{
    struct rho_bitmap *bitmap = NULL;

    bitmap = rhoL_zalloc(sizeof(*bitmap));
    bitmap->a = rhoL_mallocarray(RHO_BITMAP_ELEMS(bitlen),
            RHO_BITMAP_ELEM_SIZE, RHO_MEM_ZERO);
    bitmap->resizeable = resizeable;
    bitmap->bitlen = bitlen;

    return (bitmap);
}

struct rho_bitmap *
rho_bitmap_copy(struct rho_bitmap *bitmap)
{
    struct rho_bitmap *newp = NULL;

    newp = rho_bitmap_create(bitmap->resizeable, bitmap->bitlen);
    memcpy(newp->a, bitmap->a,
            RHO_BITMAP_ELEMS(bitmap->bitlen) * RHO_BITMAP_ELEM_SIZE);

    return (newp);
}

void
rho_bitmap_destroy(struct rho_bitmap *bitmap)
{
    rhoL_free(bitmap->a);
    rhoL_free(bitmap);
}

void
rho_bitmap_resize(struct rho_bitmap *bitmap, size_t newbitlen)
{
    size_t m = 0;
    size_t n = 0;
    size_t extra = 0;

    RHO_ASSERT(newbitlen > bitmap->bitlen);

    m = RHO_BITMAP_ELEMS(bitmap->bitlen);
    n = RHO_BITMAP_ELEMS(newbitlen);
    extra = n - m;

    if (extra) {
        bitmap->a = rhoL_reallocarray(bitmap->a, n, RHO_BITMAP_ELEM_SIZE, 0);
        rho_memzero(((uint8_t *)bitmap->a) + (m * RHO_BITMAP_ELEM_SIZE),
                extra * RHO_BITMAP_ELEM_SIZE);
    }

    bitmap->bitlen = newbitlen;
}

size_t 
rho_bitmap_size(const struct rho_bitmap *bitmap)
{
    return (bitmap->bitlen);
}

/* 0 on not set, 1 on set */
int
rho_bitmap_get(const struct rho_bitmap *bitmap, int i)
{
    int elem = 0;
    int bit = 0;

    /* TODO: better overflow checking */
    if (((size_t)i) >= bitmap->bitlen)
        rho_die("can't get bit %d; bitlen is %zu", i, bitmap->bitlen);

    elem = i / RHO_BITMAP_ELEM_BITS; 
    bit = i % RHO_BITMAP_ELEM_BITS;

    return (bitmap->a[elem] & (1 << bit)) ? 1 : 0;
}

/* return 0 on success, -1 on failure */
void
rho_bitmap_set(struct rho_bitmap *bitmap, int i)
{
    int elem = 0;
    int bit = 0;

    if (((size_t)i) >= bitmap->bitlen) {
        if (bitmap->resizeable)
            rho_bitmap_resize(bitmap, i+1);
        else
            rho_die("can't set bit %d; bitlen is %zu", i, bitmap->bitlen);
    }
    
    elem = i / RHO_BITMAP_ELEM_BITS;
    bit = i % RHO_BITMAP_ELEM_BITS;
    bitmap->a[elem] |= 1 << bit;
}

void
rho_bitmap_nset(struct rho_bitmap *bitmap, int start, int stop)
{
    (void)bitmap;
    (void)start;
    (void)stop;
    /* TODO */
}

void
rho_bitmap_clear(struct rho_bitmap *bitmap, int i)
{
    int elem = 0;
    int bit = 0;

    if (((size_t)i) >= bitmap->bitlen)
        rho_die("can't clear bit %d; bitlen is %zu", i, bitmap->bitlen);

    elem = i / RHO_BITMAP_ELEM_BITS;
    bit = i % RHO_BITMAP_ELEM_BITS;
    bitmap->a[elem] &= ~(1 << bit);
}

void
rho_bitmap_nclear(struct rho_bitmap *bitmap, int start, int stop)
{
    (void)bitmap;
    (void)start;
    (void)stop;
    /* TODO */
}

void
rho_bitmap_clearall(struct rho_bitmap *bitmap)
{
    rho_memzero((uint8_t *)bitmap->a,
            RHO_BITMAP_ELEMS(bitmap->bitlen) * RHO_BITMAP_ELEM_SIZE);
}

/* find first set -- TODO: make faster */
int
rho_bitmap_ffs(const struct rho_bitmap *bitmap)
{
    size_t i = 0;
    int elem  = 0;
    int bit = 0;
    bool found = false;

    for (i = 0; i < bitmap->bitlen; i++) {
        elem = i / RHO_BITMAP_ELEM_BITS;
        bit = i % RHO_BITMAP_ELEM_BITS;
        if (bitmap->a[elem] & (1 << bit)) {
            found = true;
            break;
        }
    }

    return (found ? (int)i : -1);
}

/* find last set */
int
rho_bitmap_fls(const struct rho_bitmap *bitmap)
{
    size_t i = 0;
    int elem  = 0;
    int bit = 0;
    int last = -1;

    for (i = 0; i < bitmap->bitlen; i++) {
        elem = i / RHO_BITMAP_ELEM_BITS;
        bit = i % RHO_BITMAP_ELEM_BITS;
        if (bitmap->a[elem] & (1 << bit))
            last = (int)i;
    }

    return (last);
}

/* find first cleared */
int
rho_bitmap_ffc(const struct rho_bitmap *bitmap)
{
    size_t i = 0;
    int elem  = 0;
    int bit = 0;
    bool found = false;

    for (i = 0; i < bitmap->bitlen; i++) {
        elem = i / RHO_BITMAP_ELEM_BITS;
        bit = i % RHO_BITMAP_ELEM_BITS;
        if (!(bitmap->a[elem] & (1 << bit))) {
            found = true;
            break;
        }
    }

    return (found ? (int)i : -1);
}

/* find last cleared */
int
rho_bitmap_flc(const struct rho_bitmap *bitmap)
{
    size_t i = 0;
    int elem  = 0;
    int bit = 0;
    int last = -1;

    for (i = 0; i < bitmap->bitlen; i++) {
        elem = i / RHO_BITMAP_ELEM_BITS;
        bit = i % RHO_BITMAP_ELEM_BITS;
        if (!(bitmap->a[elem] & (1 << bit)))
            last = (int)i;
    }

    return (last);
}
