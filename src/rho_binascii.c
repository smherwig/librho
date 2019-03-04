#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rho_log.h"

/* outbuf must be at least 2 * size; it's up to the caller
 * whether outhex is nul-terminated 
 */
void
rho_binascii_hexlify(uint8_t *bin, size_t binsize, char *outhex)
{
    size_t i = 0;
    int nput = 0;
    char hexbyte[3] = { 0 };    /* need an extra byte for nul */

    for (i = 0; i < binsize; i++) {
        nput = snprintf(hexbyte, 3, "%02x", bin[i]);
        if (nput != 2) 
            rho_die("snprintf expected to return 2, instead returned: %d\n",
                    nput);
        memcpy(outhex + (2 * i), hexbyte, 2);
    }
}

/* from kadnode */
void
rho_binascii_unhexlify(char *hex, size_t hexlen, uint8_t *outbin)
{
    size_t i = 0;
    size_t xv = 0;

    for (i = 0; i < hexlen; i++) {
        const char c = hex[i];
        if (!isxdigit(c))
            rho_die("'%c' is not a hexdigit", c);

        if (c >= 'a')
            xv += (c - 'a')  + 10;
        else if (c >= 'A')
            xv += (c - 'A') + 10;
        else
            xv += c - '0';

        if (i % 2) {
            outbin[i/2] = xv;
            xv = 0;
        } else {
            xv *= 16;
        }
    }
}

/*
 * The size needed for the ASCII output buffer (outasc) in rho_binascii_b64encode.
 * ceil(size / 3.0) * 4)
 */
size_t
rho_binascii_b64encodesize(size_t binsize)
{
    size_t q, r;
    
    q = binsize / 3;
    r = binsize % 3;

    if (r)
        q++;

    return (q * 3);
}

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
