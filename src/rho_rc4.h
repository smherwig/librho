#ifndef _RHO_RC4_H_
#define _RHO_RC4_H_

#include <stdint.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

struct rho_rc4 {
    uint8_t state[256];
    uint8_t x;
    uint8_t y;
};

struct rho_rc4 * rho_rc4_create(uint8_t *key, size_t keylen);
void rho_rc4_destroy(struct rho_rc4 *rc4);
void rho_rc4_stream(struct rho_rc4 *rc4, uint8_t *buf, size_t buflen);

RHO_DECLS_END

#endif /* !_RHO_RC4_H_ */
