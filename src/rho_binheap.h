#ifndef _RHO_BINHEAP_H_
#define _RHO_BINHEAP_H_

#include "rho_decls.h"

RHO_DECLS_BEGIN

struct rho_binheap {
    int size;
    int cap;
    void **elems;
};

struct rho_binheap * rho_binheap_create(int init_cap);
void rho_binheap_destroy(struct rho_binheap *binheap);

void rho_binheap_insert(struct rho_binheap *binheap, void *elem);
void * rho_binheap_removemin(struct rho_binheap *binheap);

RHO_DECLS_END

#endif /* ! _RHO_BINHEAP_H_ */
