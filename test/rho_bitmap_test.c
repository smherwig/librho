#include <rho.h>

#include "rho_test.h"

static void
test_resize(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 32);

    rho_bitmap_set(bm, 32);
    RHO_TEST_ASSERT(rho_bitmap_size(bm) == 33);
    RHO_TEST_ASSERT(rho_bitmap_get(bm, 32) == 1);
    RHO_TEST_ASSERT(rho_bitmap_get(bm, 31) == 0);

    rho_bitmap_destroy(bm);
}

static void
test_set(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 48);

    rho_bitmap_set(bm, 5);
    RHO_TEST_ASSERT(rho_bitmap_get(bm, 5) == 1);

    rho_bitmap_destroy(bm);
}

static void
test_clear(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 48);

    rho_bitmap_set(bm, 5);
    rho_bitmap_clear(bm, 5);
    RHO_TEST_ASSERT(rho_bitmap_get(bm, 5) == 0);

    rho_bitmap_destroy(bm);
}

static void
test_ffs(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 48);

    rho_bitmap_set(bm, 5);
    rho_bitmap_set(bm, 10);
    rho_bitmap_set(bm, 15);
    RHO_TEST_ASSERT(rho_bitmap_ffs(bm) == 5);

    rho_bitmap_destroy(bm);
}

static void
test_ffs_all_clear(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 156);

    RHO_TEST_ASSERT(rho_bitmap_ffs(bm) == -1);

    rho_bitmap_destroy(bm);
}

static void
test_fls(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 231);

    rho_bitmap_set(bm, 100);
    rho_bitmap_set(bm, 200);
    RHO_TEST_ASSERT(rho_bitmap_fls(bm) == 200);

    rho_bitmap_destroy(bm);
}

static void
test_fls_all_clear(struct rho_test *test)
{
    struct rho_bitmap *bm = rho_bitmap_create(true, 341);

    RHO_TEST_ASSERT(rho_bitmap_fls(bm) == -1);

    rho_bitmap_destroy(bm);
}

static void
test_ffc(struct rho_test *test)
{
    size_t i = 0;
    struct rho_bitmap *bm = rho_bitmap_create(true, 231);

    RHO_TEST_ASSERT(rho_bitmap_ffc(bm) == 0);

    for (i = 0; i < 51; i++)
        rho_bitmap_set(bm, i);
    RHO_TEST_ASSERT(rho_bitmap_ffc(bm) == 51);

    rho_bitmap_destroy(bm);
}

static void
test_ffc_all_set(struct rho_test *test)
{
    size_t i = 0;
    struct rho_bitmap *bm = rho_bitmap_create(true, 125);

    for (i = 0; i < 125; i++)
        rho_bitmap_set(bm, i);
    RHO_TEST_ASSERT(rho_bitmap_ffc(bm) == -1);

    rho_bitmap_destroy(bm);
}

static void
test_flc(struct rho_test *test)
{
    size_t i = 0;
    struct rho_bitmap *bm = rho_bitmap_create(true, 231);

    RHO_TEST_ASSERT(rho_bitmap_flc(bm) == 230);

    for (i = 230; i > 50; i--)
        rho_bitmap_set(bm, i);
    RHO_TEST_ASSERT(rho_bitmap_flc(bm) == 50);

    rho_bitmap_destroy(bm);
}

static void
test_flc_all_set(struct rho_test *test)
{
    size_t i = 0;
    struct rho_bitmap *bm = rho_bitmap_create(true, 125);

    for (i = 0; i < 125; i++)
        rho_bitmap_set(bm, i);
    RHO_TEST_ASSERT(rho_bitmap_flc(bm) == -1);

    rho_bitmap_destroy(bm);
}

static struct rho_test_suite_ops suite_ops = {
    .suite_init = NULL,
    .suite_fini = NULL,
    .test_init = NULL,
    .test_fini = NULL
};

static struct rho_test suite_tests[] = {
    RHO_TEST_DECL("test_resize", test_resize),
    RHO_TEST_DECL("test_set", test_set),
    RHO_TEST_DECL("test_clear", test_clear),

    RHO_TEST_DECL("test_ffs", test_ffs),
    RHO_TEST_DECL("test_ffs_all_clear", test_ffs_all_clear),

    RHO_TEST_DECL("test_fls", test_fls),
    RHO_TEST_DECL("test_fls_all_clear", test_fls_all_clear),

    RHO_TEST_DECL("test_ffc", test_ffc),
    RHO_TEST_DECL("test_ffc_all_set", test_ffc_all_set),

    RHO_TEST_DECL("test_flc", test_flc),
    RHO_TEST_DECL("test_flc_all_set", test_flc_all_set),
    RHO_TEST_SENTINEL
};

int
main(int argc, char *argv[])
{
    struct rho_test_suite suite;

    (void)argc;
    (void)argv;

    RHO_TEST_SUITE_INIT(&suite, "bitmap", &suite_ops, suite_tests);
    rho_test_suite_run(&suite);

    return (0);
}
