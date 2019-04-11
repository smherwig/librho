#ifndef _RHO_BASE32_H_
#define _RHO_BASE32_H_

/**
 * @file    rho_base32.h
 * @brief   Base32 encoding and decoding
 *
 * Functions to Base32 encode and decode.
 *
 * The encoding turns 5 bytes into 8 bytes:
 *
 * byte0           | byte1           | byte2           | byte3           |  byte4
 * 7 6 5 4 3 2 1 0 | 7 6 5 4 3 2 1 0 | 7 6 5 4 3 2 1 0 | 7 6 5 4 3 2 1 0 | 7 6 5 4 3 2 1 0
 *          ^      |    ^         ^  |        ^        |  ^         ^    |      ^
 * ---------^-----------^---------^-----------^-----------^---------^-----------^---------
 * chunk0   ^chunk1     ^chunk2   ^chunk3     ^chunk4     ^chunk5   ^chunk6     ^chunk7
 *
 * On encoding, a chunk value of 0 encodes to 'A', 1 to 'B', ..., 25 to 'Z', 26 to '2', 27 to '3',
 * ..., and 31 to '7'.
 *
 * On decoding, the input characters must be between '2' (decimal 50)
 * and 'Z' (decimal 90)
 *
 * @author Stephen Herwig (smherwig)
 */


#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

size_t rho_base32_encoded_size(size_t decoded_size);
size_t rho_base32_decoded_size(size_t encoded_size);

/**
 * @brief Base32 encode a buffer.
 *
 * Base32 encodes the in buffer of size len, and places encoding in out.
 * The encoding alphabet is [A-Z2-9].  The out buffer must be at least
 * ceil(len / 5.0) * 8 bytes long; this value can be computed by calling
 * rho_base32_encoding_size(len).  The out buffer is not nul-terminated.
 *
 * @param in input byte buffer
 * @param len length of in
 * @param out the output buffer for the Base32 encoded data
 *
 * @return The size of the ouput buffer
 */
size_t rho_base32_encode(const uint8_t *in, size_t len, char *out);


/**
 * @brief Base32 decode a buffer.
 *
 * Base32 decodes the in buffer of size len, and places encoding in out.
 * The encoding alphabet is [A-Z2-9].  The out buffer must be at least
 * ceil(len / 5.0) * 8 bytes long; this value can be computed by calling
 * rho_base32_encoding_size(len).  The out buffer is not nul-terminated.
 *
 * @param in input byte buffer
 * @param len length of in
 * @param out the output buffer for the Base32 encoded data
 *
 * @return The size of the ouput buffer
 */
ssize_t rho_base32_decode(const char *in, size_t len, uint8_t *out);

RHO_DECLS_END

#endif /* _RHO_BASE32_H_ */
