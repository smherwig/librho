#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rho_base32.h"
#include "rho_log.h"

/* 
 * TODO: understand how << and >> work with signed and unsigned values
 *
 * signed:
 *  right shift of a negative signe dnumber has implementation-defined behavior
 *  most compilers will fill with the sign bit.
 *
 * unsigned
 *  right shift fills in 0s on the left (so, a logical shift)
 *
 *
 * If you left-shift a signed numbre so that the sign bit is affect, the result
 * is undefined.
 *                   01234567
 *  encode('a')    : ME======  
 *  encode('ab')   : MFRA====
 *  encode('abc')  : MFRGG===
 *  encode('abcd') : MFRGGZA=
 *  encode('abcde'): MFRGGZDF
 *
 */

#define RHO_BASE32_VALID_CHAR(c) \
    (((c) >= 'A' && (c) <= 'Z') || ((c) >= '2' && (c) <= '7'))

static char *enc  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int8_t dec[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
    -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,
     5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25
};


size_t
rho_base32_encoded_size(size_t decoded_size)
{
    size_t q, r;

    q = decoded_size / 5;
    r = decoded_size % 5;

    if (r)
        q++;

    return (q * 8);
}

/* TODO: */
size_t
rho_base32_decoded_size(size_t encoded_size)
{
    size_t q, r;

    q = encoded_size / 5;
    r = encoded_size % 5;

    if (r)
        q++;

    return (q * 8);
}

size_t
rho_base32_encode(const uint8_t *in, size_t len, char *out)
{  
    char *start = out;

    do {
        *out++ = enc[(in[0] & 0xf8) >> 3];

        if (len == 1) {
            *out++ = enc[(in[0] & 0x07) << 2];
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            break;
        }

        *out++ = enc[((in[0] & 0x07) << 2) | ((in[1] & 0xc0) >> 6)];
        *out++ = enc[ (in[1] & 0x3e) >> 1];

        if (len == 2) {
            *out++ = enc[(in[1] & 0x01) << 4];
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            break;
        }

        *out++ = enc[((in[1] & 0x01) << 4) | ((in[2] & 0xf0) >> 4)];

        if (len == 3) {
            *out++ = enc[(in[2] & 0x0f) << 1];
            *out++ = '=';
            *out++ = '=';
            *out++ = '=';
            break;
        }

        *out++ = enc[((in[2] & 0x0f) << 1) | ((in[3] & 0x80) >> 7)];
        *out++ = enc[( in[3] & 0x7c) >> 2];

        if (len == 4) {
            *out++ = enc[(in[3] & 0x03) << 3];
            *out++ = '=';
            break;
        }

        *out++ = enc[((in[3] & 0x03) << 3) | ((in[4] & 0xe0) >> 5)];
        *out++ = enc[ (in[4] & 0x1f)];

        in += 5;
    } while (len -= 5);

    return (start - out);;
}

ssize_t
rho_base32_decode(const char *in, size_t len, uint8_t *out)
{
    int8_t d0, d1, d2, d3, d4, d5, d6, d7;
    int i = 0;
    int j = 0;
    ssize_t outlen = 0;
    bool equal_flag = false;

    /* len must be a multiple of 8 */
    if ((len % 8) != 0) {
        rho_warn("invalid base32 encoding: length (%zu) is not a multiple of 8", len);
        outlen = -1;
        goto done;
    }

    if (len == 0)
        goto done;

    do {
        /* 
         * detect more base32 characters following final '=' characters (from
         * previous round of processing)
         */
        if (equal_flag) {
            rho_warn("invalid base32 encoding: characters following '='");
            outlen = -1;
            goto done;
        }

        /* check for valid base32 characters */
        for (i = 0; i < 8; i++) {
            if (!RHO_BASE32_VALID_CHAR(in[i])) {
                if (in[i] == '=') {
                    equal_flag = true;
                    if ((i != 2) && (i != 4) && (i != 5) && (i != 7)) {
                        rho_warn("invalid base32 encoding: bad '='");
                        outlen = -1;
                        goto done;
                    }
                    for (j = i; j < 8; j++) {
                        if (in[j] != '=') {
                            rho_warn("invalid base32 encoding: value ('%c') following '='", in[j]);
                            outlen = -1;
                            goto done;
                        }
                    }
                } else {
                    rho_warn("invalid base32 encoding: illegal value '%c'", in[i]);
                    outlen = -1;
                    goto done;
                }
            }
        }

        /* 
         * can't use dec[in[0]] because compiler warns that array subscripts
         * (the subscripts for dec) can't be signed types.
         */
        d0 = dec[(unsigned char)in[0]];
        d1 = dec[(unsigned char)in[1]];
        *out++ = (d0 << 3) |  (d1 >> 2);
        outlen++;

        if (in[2] != '=') {
            d2 = dec[(unsigned char)in[2]];
            d3 = dec[(unsigned char)in[3]];
            *out++ = ((d1 & 0x03) << 6) | (d2 << 1) | (d3 >> 4);
            outlen++;
        }

        if (in[4] != '=') {
            d4 = dec[(unsigned char)in[4]];
            *out++ = ((d3 & 0x0f) << 4) | (d4 >> 1);
            outlen++;
        }

        if (in[5] != '=') {
            d5 = dec[(unsigned char)in[5]];
            d6 = dec[(unsigned char)in[6]];
            *out++ = ((d4 & 0x01) << 7) | (d5 << 2) | (d6 >> 5);
            outlen++;
        }

        if (in[7] != '=') {
            d7 = dec[(unsigned char)in[7]];
            *out++ = ((d6 & 0x07) << 5) | d7;
            outlen++;
        }

        in += 8;
    } while (len -= 8);

done:
    return (outlen);
}
