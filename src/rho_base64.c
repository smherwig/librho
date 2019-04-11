#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rho_base64.h"
#include "rho_log.h"

/*
 * Base64 dives teh input into 6-bit chunks (2^6 = 64), and maps each 6-bit
 * chucnk to one of the printable ASCII characters.  A-Z, a-z, and 0-9 occumpu
 * the first 62 characters in this map; the remaining two are
 * conventionally '+', and '/', although there is some application deviation.
 *
 * Since a byte stream might not divide evenly into 6-bit chunks, the following
 * padding scheme is used:
 *
 *  - if the stream has one byte leftover, the encoder adds two '='
 *  - if the stream has two bytes leftover, the encoder adds one '='.
 *
 * Since 6 bits get mapped into 8 bits, The encoding is 1/3 bigger than the
 * original stream.
 */

/*
 * '+' (43) => 62
 * '/' (47) => 63
 * '0' (48) => 52
 * ...
 * '9' (57) => 61
 * 'A' (65) => 0 
 * ...
 * 'Z' (90) => 25
 * 'a' (97) => 26
 * ...
 * 'z' (122) => 51
 */

static char *base64  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int unbase64[] = {
  -1,   -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,   -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,   -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1, 
  -1,   -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,     -1,
  -1,   -1,     -1,     62,     -1,     -1,     -1,     63,     52,     53, 
  54,   55,     56,     57,     58,     59,     60,     61,     -1,     -1, 
  -1,   0,      -1,     -1,     -1,     0,      1,      2,      3,      4, 
  5,    6,      7,      8,      9,      10,     11,     12,     13,     14, 
  15,   16,     17,     18,     19,     20,     21,     22,     23,     24, 
  25,   -1,     -1,     -1,     -1,     -1,     -1,     26,     27,     28,
  29,   30,     31,     32,     33,     34,     35,     36,     37,     38, 
  39,   40,     41,     42,     43,     44,     45,     46,     47,     48, 
  49,   50,     51,     -1,     -1,     -1,     -1,     -1,     -1
}; 

/*
 * The size needed for the ASCII output buffer (outasc) in rho_binascii_b64encode.
 * ceil(size / 3.0) * 4)
 */
size_t
rho_base64_encoded_size(size_t decoded_size)
{
    size_t q, r;
    
    q = decoded_size / 3;
    r = decoded_size % 3;

    if (r)
        q++;

    return (q * 4);
}

/* TODO: */
size_t
rho_base64_decoded_size(size_t encoded_size)
{
    size_t q, r;
    
    q = encoded_size / 3;
    r = encoded_size % 3;

    if (r)
        q++;

    return (q * 4);
}

#if 0
    /* OLD VERSION */

 #define B64ENCGET_1(a)     ((0xfc & (a)) >> 2)
 #define B64ENCGET_2(a,b)   ( ((0x03 & (a)) << 4)  | ((0xf0 & (b)) >> 4) )
 #define B64ENCGET_3(b,c)   ( ((0x0f & (b)) << 2)  | ((0xc0 & (c)) >> 6) )
 #define B64ENCGET_4(c)     (0x3f & (c))

static char b64enclut[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

/* 
 * altchars should either be null or a string of length 2, specifying the
 * characters for codes 62 (default '+') and 63 (default '/').
 */
void
rho_binascii_b64encode(uint8_t *bin, size_t binsize, char *outasc, const char *altchars)
{
    size_t i = 0;
    size_t j = 0;
    size_t leftover = 0;
    uint8_t a, b, c; 
    int code = 0;

    if (binsize < 3) {
        if (binsize == 0) {
            goto done;
        } else if (binsize == 1) {
            a = bin[binsize - 1];
            code = b64enclut[B64ENCGET_1(a)];     
            if (altchars != NULL) {
                if      (code == 62) outasc[j] = altchars[0];
                else if (code == 63) outasc[j] = altchars[1];
                else                 outasc[j] = b64enclut[code];
            }
            j++;
            outasc[j] = '=';
        } else {
            /* 2 */
            a = bin[binsize - 2];
            b = bin[binsize - 1];

            code = b64enclut[B64ENCGET_1(a)];     
            if (altchars != NULL) {
                if      (code == 62) outasc[j] = altchars[0];
                else if (code == 63) outasc[j] = altchars[1];
                else                 outasc[j] = b64enclut[code];
            }
            j++;

            code = b64enclut[B64ENCGET_2(a, b)];     
            if (altchars != NULL) {
                if      (code == 62) outasc[j] = altchars[0];
                else if (code == 63) outasc[j] = altchars[1];
                else                 outasc[j] = b64enclut[code];
            }
            j++;
            outasc[j] = '=';
        }
    }

    j = 0;
    for (i = 0; i < binsize; i += 3) {
        a = bin[i]; 
        b = bin[i + 1];
        c = bin[i + 2]; 

        code = b64enclut[B64ENCGET_1(a)];     
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;

        code = b64enclut[B64ENCGET_2(a, b)];     
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;

        code = b64enclut[B64ENCGET_3(b,c)];   
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;

        code = b64enclut[B64ENCGET_4(c)];
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;
    }

    leftover = binsize % 3;
    if (leftover == 0) {
        goto done;
    } else if (leftover == 1) {
        a = bin[binsize - 1];
        code = b64enclut[B64ENCGET_1(a)];     
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;
        outasc[j] = '=';
    } else {
        /* 2 */
        a = bin[binsize - 2];
        b = bin[binsize - 1];

        code = b64enclut[B64ENCGET_1(a)];     
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;

        code = b64enclut[B64ENCGET_2(a, b)];     
        if (altchars != NULL) {
            if      (code == 62) outasc[j] = altchars[0];
            else if (code == 63) outasc[j] = altchars[1];
            else                 outasc[j] = b64enclut[code];
        }
        j++;
        outasc[j] = '=';
    }

done:
    return;
}
#endif

size_t
rho_base64_encode(const uint8_t *in, size_t len, char *out)
{  
    char *start = out;

    do {
        *out++ = base64[(in[0] & 0xFC) >> 2];
  
        if (len == 1) {
            *out++ = base64[((in[0] & 0x03) << 4)];
            *out++ = '=';
            *out++ = '=';
            break;
        }

        *out++ = base64[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];

        if (len == 2) {
            *out++ = base64[((in[1] & 0x0F) << 2)];
            *out++ = '=';
            break;
        }

        *out++ = base64[((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6)];
        *out++ = base64[(in[2] & 0x3F)];

        in += 3;
    } while (len -= 3);

    *out = '\0';

    return (start - out);
}

ssize_t
rho_base64_decode(const char *in, size_t len, uint8_t *out)
{
    int i = 0;
    ssize_t outlen = 0;

    /* input must be a multiple of 4 (e.g., low 2-bits are 0) */
    RHO_ASSERT(!(len & 0x03));

    do {
        /* Check for illegal base64 characters */
        for (i = 0; i <= 3; i++ ) {
            /* TODO: better check */
            if (unbase64[(unsigned char)in[i]] == -1 ) {
                rho_warn("invalid character for base64 encoding: %c\n", in[i]);
                return (-1);
            }
        }

        *out++ = (unbase64[(unsigned char)in[0]] << 2) | ((unbase64[(unsigned char)in[1]] & 0x30) >> 4);
        outlen++;

        if (in[2] != '=') {
          *out++ = ((unbase64[(unsigned char)in[1]] & 0x0F) << 4) | (unbase64[(unsigned char)in[2]] & 0x3C) >> 2;
          outlen++;
        }
      
        if (in[3] != '=') {
          *out++ = ((unbase64[(unsigned char)in[2]] & 0x03) << 6) | unbase64[(unsigned char)in[3]];
          outlen++;
        } 
        in += 4;
    } while (len -= 4); 

    /* TODO: check overflow */
    return (outlen);
}
