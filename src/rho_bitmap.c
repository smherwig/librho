#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "rho_bitmap.h"
#include "rho_log.h"
#include "rho_mem.h"

#define RHO_BITMAP_NBYTESELEM 4 /* sizeof(uint32_t) */
#define RHO_BITMAP_NBITSELEM 32

#define RHO_BITMAP_MAXELEMS(maxbits) \
    (((maxbits) / RHO_BITMAP_NBITSELEM) + \
     (((maxbits) % RHO_BITMAP_NBITSELEM) ? 1 : 0))

#define RHO_BITMAP_NBYTES(maxbits) \
     (RHO_BITMAP_MAXELEMS((maxbits)) * RHO_BITMAP_NBYTESELEM)


struct rho_bitmap *
rho_bitmap_create(bool resizeable, size_t maxbits)
{
    struct rho_bitmap *bitmap = NULL;

    bitmap = rhoL_zalloc(sizeof(*bitmap));
    bitmap->a = rhoL_zalloc(RHO_BITMAP_NBYTES(maxbits));
    bitmap->resizeable = resizeable;
    bitmap->maxbits = maxbits;

    return (bitmap);
}

struct rho_bitmap *
rho_bitmap_copy(struct rho_bitmap *bitmap)
{
    struct rho_bitmap *newp = NULL;
    size_t nbytes = 0;

    newp = rhoL_zalloc(sizeof(*bitmap));

    nbytes = RHO_BITMAP_NBYTES(bitmap->maxbits);
    newp->a = rhoL_zalloc(RHO_BITMAP_NBYTES(nbytes));
    memcpy(newp->a, bitmap->a, nbytes);

    newp->resizeable = bitmap->resizeable;
    newp->maxbits = bitmap->maxbits;

    return (newp);
}

void
rho_bitmap_destroy(struct rho_bitmap *bitmap)
{
    rhoL_free(bitmap->a);
    rhoL_free(bitmap);
}

void
rho_bitmap_resize(struct rho_bitmap *bitmap, size_t newmaxbits)
{
    bitmap->a = rhoL_realloc(bitmap, RHO_BITMAP_NBYTES(newmaxbits));
    bitmap->maxbits = newmaxbits;
}

size_t 
rho_bitmap_size(const struct rho_bitmap *bitmap)
{
    return (bitmap->maxbits);
}

/* 0 on not set, 1 on set */
int
rho_bitmap_get(const struct rho_bitmap *bitmap, int i)
{
    int elem = 0;
    int bit = 0;

    /* TODO: better overflow checking */
    if (((size_t)i) > bitmap->maxbits)
        rho_die("can't set bit %d; maxbits is %zu", i, bitmap->maxbits);

    elem = i / RHO_BITMAP_NBITSELEM; 
    bit = i % RHO_BITMAP_NBITSELEM;

    return (bitmap->a[elem] & (1 << bit)) ? 1 : 0;
}

/* return 0 on success, -1 on failure */
void
rho_bitmap_set(struct rho_bitmap *bitmap, int i)
{
    int elem = 0;
    int bit = 0;

    if (((size_t)i) > bitmap->maxbits) {
        if (bitmap->resizeable)
            rho_bitmap_resize(bitmap, i);
        else
            rho_die("can't set bit %d; maxbits is %zu", i, bitmap->maxbits);
    }
    
    elem = i / RHO_BITMAP_NBITSELEM;
    bit = i % RHO_BITMAP_NBITSELEM;
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

    if (((size_t)i) > bitmap->maxbits)
        rho_die("can't set bit %d; maxbits is %zu", i, bitmap->maxbits);

    elem = i / RHO_BITMAP_NBITSELEM;
    bit = i % RHO_BITMAP_NBITSELEM;
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
    memset(bitmap->a, 0x00,
            RHO_BITMAP_MAXELEMS(bitmap->maxbits) * RHO_BITMAP_NBYTESELEM);
}


/* find first set -- TODO: make faster */
int
rho_bitmap_ffs(const struct rho_bitmap *bitmap)
{
    size_t i = 0;
    int elem  = 0;
    int bit = 0;
    bool found = false;

    for (i = 0; i < bitmap->maxbits; i++) {
        elem = i / RHO_BITMAP_NBITSELEM;
        bit = i % RHO_BITMAP_NBITSELEM;
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

    for (i = 0; i < bitmap->maxbits; i++) {
        elem = i / RHO_BITMAP_NBITSELEM;
        bit = i % RHO_BITMAP_NBITSELEM;
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

    for (i = 0; i < bitmap->maxbits; i++) {
        elem = i / RHO_BITMAP_NBITSELEM;
        bit = i % RHO_BITMAP_NBITSELEM;
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

    for (i = 0; i < bitmap->maxbits; i++) {
        elem = i / RHO_BITMAP_NBITSELEM;
        bit = i % RHO_BITMAP_NBITSELEM;
        if (!(bitmap->a[elem] & (1 << bit)))
            last = (int)i;
    }

    return (last);
}
