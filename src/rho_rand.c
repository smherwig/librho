#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rho_rand.h"

/* TODO: use a better PRNG; seed if not seeded */

void
rho_rand_seed()
{
}

void
rho_rand_bytes(uint8_t *buf, size_t size)
{
    size_t i = 0;

    for (i = 0; i < size; i++)
        buf[i] = rand() % 256;
}

uint8_t
rho_rand_u8(void)
{
    uint8_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint16_t
rho_rand_u16(void)
{
    uint16_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint32_t
rho_rand_32(void)
{
    uint32_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint64_t
rho_rand_u64(void)
{
    uint64_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}
