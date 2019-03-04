#ifndef _RHO_BITMAP_H_
#define _RHO_BITMAP_H_

#include <stdbool.h>
#include <stdint.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

/* only expand on sets, not gets */
struct rho_bitmap {
    bool resizeable;
    size_t maxbits;
    uint32_t *a;
};

struct rho_bitmap * rho_bitmap_create(bool resizeable, size_t maxbits);
struct rho_bitmap * rho_bitmap_copy(struct rho_bitmap *bitmap);
void rho_bitmap_destroy(struct rho_bitmap *bitmap);

void rho_bitmap_resize(struct rho_bitmap *bitmap, size_t newmaxbits);

size_t rho_bitmap_size(const struct rho_bitmap *bitmap);

int rho_bitmap_get(const struct rho_bitmap *bitmap, int i);
void rho_bitmap_set(struct rho_bitmap *bitmap, int i);
void rho_bitmap_nset(struct rho_bitmap *bitmap, int start, int stop);
void rho_bitmap_clear(struct rho_bitmap *bitmap, int i);
void rho_bitmap_nclear(struct rho_bitmap *bitmap, int start, int stop);
void rho_bitmap_clearall(struct rho_bitmap *bitmap);

#define rho_bitmap_isset(bitmap, i) rho_bitmap_get(bitmap, i)

int rho_bitmap_ffs(const struct rho_bitmap *bitmap);
int rho_bitmap_fls(const struct rho_bitmap *bitmap);
int rho_bitmap_ffc(const struct rho_bitmap *bitmap);
int rho_bitmap_flc(const struct rho_bitmap *bitmap);

/* 
 * FIXME: this is wrong; there's no clean way to do foreach_set, so just do
 * foreach (RHO_BITMAP_FOREACH(i, val, bitmap)), and have the client craft
 * the body of the for-loop to do a continue on unset values
 */
#define RHO_BITMAP_FOREACH(i, val, bitmap) \
    for ( \
            (i) = 0, (val) = rho_bitmap_get((bitmap), (i)); \
            ((i) < (bitmap)->maxbits); \
            (i)++,   (val) = rho_bitmap_get((bitmap), (i)) \
        )

/* TODO: 
 *
 * setall
 * toggle
 * ntoggle
 *
 * anyclr?
 * allclr?
 * anyset?
 * allset?
 *
 * operations on two bitmaps 
 */

RHO_DECLS_END

#endif /* ! _RHO_BITMAP_H_ */
