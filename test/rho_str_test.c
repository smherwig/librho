#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rho.h>

#include "rho_test.h"

struct strlcpy_test {
    const char *src;
    const char *expected_dst;
    size_t  expected_ret;
};

/* assumes dst_size is 4 */
struct strlcpy_test strlcpy_tests[] = {
    {"",        "",     0},
    {"a",       "a",    1},
    {"ab",      "ab",   2},
    {"abc",     "abc",  3},
    {"abcd",    "abc",  4},
    {"abcde",   "abc",  5},
    {NULL,      NULL,   0}
};

static void 
test_strlcpy(struct rho_test *test)
{
    size_t ret = 0;
    char dst[4] = { 0 };
    struct strlcpy_test *t = NULL;

    for (t = strlcpy_tests; t->src != NULL; t++) {
        ret = rho_strlcpy(dst, t->src, RHO_C_ARRAY_SIZE(dst));
        RHO_TEST_ASSERT(strcmp(dst, t->expected_dst) == 0);
        RHO_TEST_ASSERT(ret == t->expected_ret);
        memset(dst, 0x00, RHO_C_ARRAY_SIZE(dst));
    }
}

static void 
test_strlcpy_0dstsize(struct rho_test *test)
{
    size_t ret = 0;
    char dst[4] = { 0 };

    ret = rho_strlcpy(dst, "abc", 0);
    RHO_TEST_ASSERT(ret == 3);
}

static struct rho_test_suite_ops suite_ops = {
    .suite_init = NULL,
    .suite_fini = NULL,
    .test_init = NULL,
    .test_fini = NULL
};

static struct rho_test suite_tests[] = {
    RHO_TEST_DECL("strlcpy", test_strlcpy),
    RHO_TEST_DECL("strlcpy_0dstsize", test_strlcpy_0dstsize),
    RHO_TEST_SENTINEL
};

int
main(int argc, char *argv[])
{
    struct rho_test_suite suite;

    (void)argc;
    (void)argv;

    RHO_TEST_SUITE_INIT(&suite, "str", &suite_ops, suite_tests);
    rho_test_suite_run(&suite);

    return (0);
}
