#ifndef _RHO_BITOPS_H_
#define _RHO_BITOPS_H_

#include "rho_decls.h"

RHO_DECLS_BEGIN

/*                     
 * Assumes array is of type unsigned char.
 * Bits numbers increase from left to right:
 *
 *                       111111
 *   bit #: 01234567 | 89012345
 * example: 00000000 | 01000000
 */
#define RHO_BITOPS_ISSET(a, bit) \
    ((a)[(int)((bit) / 8)] & (0x80 >> ((bit) % 8)))

#define RHO_BITOPS_SET(a, bit) \
    ((a)[(int)((bit) / 8)] |= (0x80 >> ((bit) % 8)))

#define RHO_BITOPS_CLR(a, bit) \
    ((a)[(int)((bit) / 8)] &= ~(0x80 >> ((bit) % 8)))

RHO_DECLS_END

#endif /* _RHO_BITOPS_H_ */
