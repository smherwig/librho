#include <stdint.h>
#include <string.h>

#include "rho_mem.h"
#include "rho_rc4.h"

static void
swap_byte(uint8_t *a, uint8_t *b)
{
    uint8_t tmp = 0;

    tmp = *a;
    *a = *b;
    *b = tmp;
}

struct rho_rc4 *
rho_rc4_create(uint8_t *key, size_t keylen)
{
    struct rho_rc4 *rc4 = NULL;
    size_t i = 0;
    uint8_t x = 0;
    uint8_t *state = NULL;

    rc4 = rhoL_calloc(1, sizeof(*rc4));

    state = rc4->state;
    for (i = 0; i < 256; i++)
        state[i] = i; 

    for (i = 0; i < 256; i++) {
        x = (x + state[i] + key[(i % keylen)]) % 256;
        swap_byte(&state[i], &state[x]);
    }

    return (rc4);
}

void
rho_rc4_destroy(struct rho_rc4 *rc4)
{
    rhoL_free(rc4);
}

void
rho_rc4_stream(struct rho_rc4 *rc4, uint8_t *buf, size_t buflen)
{
    uint8_t x = 0;
    uint8_t y = 0;
    uint8_t *state = NULL;
    size_t i = 0;

    x = rc4->x;
    y = rc4->y;
    state = rc4->state;

    for (i = 0; i < buflen; i++) {
        x = (x + 1) % 256;
        y = (y + state[x]) % 256;
        swap_byte(&state[x], &state[y]);
        buf[i] ^= state[ (state[x] + state[y]) % 256 ];
    }

    rc4->x = x;
    rc4->y = y;
}

#if 0
int
main(int argc, char *argv[])
{
    uint8_t buf[] = "Hello, World!";
    uint8_t *key = "Grace"; 
    struct rho_rc4 *rc4 = NULL;

    rc4 = rho_rc4_create(key, strlen(key));
    rho_rc4_stream(rc4, buf, 13);
    rho_hexdump(buf, 13, "encrypted"); 
    rho_rc4_destroy(rc4);

    rc4 = rho_rc4_create(key, strlen(key));
    rho_rc4_stream(rc4, buf, 13);
    rho_hexdump(buf, 13, "decrypted"); 
    printf("%s\n", buf);
    rho_rc4_destroy(rc4);

    return (0);
}
#endif
