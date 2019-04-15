#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rho.h>

#include "rho_test.h"

struct test_data {
    const uint8_t *bytes;
    size_t bytes_len;
    const char *ascii;
    size_t ascii_len;
};

struct test_data g_test_data[] = {
    {(const uint8_t *)"a", 1, "ME======", 8},
    {(const uint8_t *)"ab", 2, "MFRA====", 8},
    {(const uint8_t *)"abc", 3, "MFRGG===", 8},
    {(const uint8_t *)"abcd", 4, "MFRGGZA=", 8},
    {(const uint8_t *)"abcde", 5, "MFRGGZDF=", 8},
    
    {(const uint8_t* )"The quick brown fox jumps over the lazy dog",
    43,
    "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO===",
    72},

    { NULL, 0, NULL, 0}
};

static void 
test_encode(struct rho_test *test)
{
    int i = 0;
    struct test_data *d = NULL;
    char encoded[128] = { 0 };

    d = &(g_test_data[i]);
    while (d->bytes != NULL) {
        printf("encode (%d): \"%s\"\n", i, (const char *)d->bytes);
        printf("encoded_size: %zu\n", rho_base32_encoded_size(d->bytes_len));
        RHO_TEST_ASSERT(rho_base32_encoded_size(d->bytes_len) == d->ascii_len);
        rho_base32_encode((const uint8_t *)d->bytes, d->bytes_len, encoded);
        RHO_TEST_ASSERT(rho_mem_equal(encoded, d->ascii, d->ascii_len));
        i++;
        d = &(g_test_data[i]);
    }
}

static void 
test_decode(struct rho_test *test)
{
    int i = 0;
    struct test_data *d = NULL;
    uint8_t decoded[128] = { 0 };

    d = &(g_test_data[i]);
    while (d->bytes != NULL) {
        printf("decode (%d): \"%s\"\n", i, d->ascii);
        RHO_TEST_ASSERT(rho_base32_decoded_size(d->ascii_len) == d->bytes_len);
        rho_base32_decode(d->ascii, d->ascii_len, decoded);
        RHO_TEST_ASSERT(rho_mem_equal(decoded, d->bytes, d->bytes_len));
        i++;
        d = &(g_test_data[i]);
    }
}

static struct rho_test_suite_ops suite_ops = {
    .suite_init = NULL,
    .suite_fini = NULL,
    .test_init = NULL,
    .test_fini = NULL
};

static struct rho_test suite_tests[] = {
    RHO_TEST_DECL("encode", test_encode),
    RHO_TEST_DECL("decode", test_decode),
    RHO_TEST_SENTINEL
};

int
main(int argc, char *argv[])
{
    struct rho_test_suite suite;

    (void)argc;
    (void)argv;

    RHO_TEST_SUITE_INIT(&suite, "base32", &suite_ops, suite_tests);
    rho_test_suite_run(&suite);

    return (0);
}
