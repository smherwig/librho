#ifndef _RHO_BASE64_H_
#define _RHO_BASE64_H_

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

size_t rho_base64_encoded_size(size_t decoded_size);
size_t rho_base64_decoded_size(size_t encoded_size);

size_t rho_base64_encode(const uint8_t *in, size_t len, char *out);
ssize_t rho_base64_decode(const char *in, size_t len, uint8_t *out);

RHO_DECLS_END

#endif /* _RHO_BASE64_H_ */
