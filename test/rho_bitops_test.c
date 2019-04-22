#include <inttypes.h>
#include <stdint.h>

#include <rho.h>

#include "rho_test.h"

static void
test_u32_set(struct rho_test *test)
{
    size_t i = 0;
    uint32_t a = 0;
    int val = 0;

    RHO_BITOPS_SET((uint8_t *)&a, 8);
    printf("a=%"PRIu32"\n", a);

    (void)test;

    RHO_BITOPS_FOREACH(i, val, ((uint8_t*)&a), 32) {
        printf("bit %zu: %d\n", i, val);
#if 0
        if (i == 8)
            RHO_TEST_ASSERT(val == 1);
        else
            RHO_TEST_ASSERT(val == 0);
#endif
    }
}

static struct rho_test_suite_ops suite_ops = {
    .suite_init = NULL,
    .suite_fini = NULL,
    .test_init = NULL,
    .test_fini = NULL
};

static struct rho_test suite_tests[] = {
    RHO_TEST_DECL("u32_set", test_u32_set),
    RHO_TEST_SENTINEL
};

int
main(int argc, char *argv[])
{
    struct rho_test_suite suite;

    (void)argc;
    (void)argv;

    RHO_TEST_SUITE_INIT(&suite, "bitops", &suite_ops, suite_tests);
    rho_test_suite_run(&suite);

    return (0);
}
