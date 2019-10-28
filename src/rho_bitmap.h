#ifndef _RHO_BITMAP_H_
#define _RHO_BITMAP_H_

#include <stdbool.h>
#include <stdint.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

/* only expand on sets, not gets */
struct rho_bitmap {
    bool resizeable;
    size_t bitlen;
    uint32_t *a;
};

struct rho_bitmap * rho_bitmap_create(bool resizeable, size_t bitlen);
struct rho_bitmap * rho_bitmap_copy(struct rho_bitmap *bitmap);
void rho_bitmap_destroy(struct rho_bitmap *bitmap);

void rho_bitmap_resize(struct rho_bitmap *bitmap, size_t newbitlen);

#define rho_bitmap_size(bitmap) (bitmap)->bitlen

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

RHO_DECLS_END

#endif /* ! _RHO_BITMAP_H_ */
