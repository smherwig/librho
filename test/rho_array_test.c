#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rho.h>

#include "rho_test.h"

static void
test_auto_int(struct rho_test *test)
{
    RHO_ARRAY_DECLARE(my_int_array, int) array = RHO_ARRAY_INIT(int);
    int val = 0;
    size_t i = 0;
    size_t size = 0;

    RHO_ARRAY_INSERT(&array, 0, 10);
    RHO_ARRAY_INSERT(&array, 1, 20);
    RHO_ARRAY_INSERT(&array, 2, 30);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(&array) == 3);

    RHO_ARRAY_REMOVE(val, &array, 1);
    RHO_TEST_ASSERT(val == 20);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(&array) == 2);

    int expect[] = {10, 30};
    size = RHO_ARRAY_SIZE(&array);
    for (i = 0; i < size; i++) {
        RHO_ARRAY_GET(val, &array, i);
        RHO_TEST_ASSERT(val == expect[i]);
    }

    RHO_ARRAY_CLEAR(&array);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(&array) == 0);
}

static void 
test_heap_int(struct rho_test *test)
{
    RHO_ARRAY_DECLARE(my_int_array, int);
    struct  my_int_array *array = NULL;
    int val = 0;
    size_t i = 0;
    size_t size = 0;

    RHO_ARRAY_ALLOC_INIT(array, int);

    RHO_ARRAY_INSERT(array, 0, 10);
    RHO_ARRAY_INSERT(array, 1, 20);
    RHO_ARRAY_INSERT(array, 2, 30);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(array) == 3);

    RHO_ARRAY_REMOVE(val, array, 1);
    RHO_TEST_ASSERT(val == 20);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(array) == 2);

    int expect[] = {10, 30};
    size = RHO_ARRAY_SIZE(array);
    for (i = 0; i < size; i++) {
        RHO_ARRAY_GET(val, array, i);
        RHO_TEST_ASSERT(val == expect[i]);
    }

    RHO_ARRAY_CLEAR(array);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(array) == 0);
    rhoL_free(array);
}

struct obj {
    int bar;
};

static struct obj *
obj_create(int bar) 
{ 
    struct obj *p = rhoL_zalloc(sizeof(*p));
    p->bar = bar;
    return (p);
} 

static void
obj_destroy(struct obj *p)
{
    rhoL_free(p);
}

static void 
test_auto_obj(struct rho_test *test)
{
    RHO_ARRAY_DECLARE(my_obj_array, struct obj *) array = RHO_ARRAY_INIT(struct obj *);
    struct obj *p = NULL;
    size_t i = 0;
    size_t size = 0;

    p = obj_create(10); RHO_ARRAY_INSERT(&array, 0, p);
    p = obj_create(20); RHO_ARRAY_INSERT(&array, 1, p);
    p = obj_create(30); RHO_ARRAY_INSERT(&array, 2, p);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(&array) == 3);

#if 0
    for (i = 0; i < RHO_ARRAY_SIZE(&array); i++) {
        RHO_ARRAY_GET(p, &array, i);
        fprintf(stderr, "a[%zu] = %d\n", i, p->bar);
    }
#endif

    RHO_ARRAY_REMOVE(p, &array, 1);
    RHO_TEST_ASSERT(p->bar == 20);
    obj_destroy(p);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(&array) == 2);

    int expect[] = {10, 30};
    size = RHO_ARRAY_SIZE(&array);
    for (i = 0; i < size; i++) {
        RHO_ARRAY_GET(p, &array, i);
        RHO_TEST_ASSERT(p->bar == expect[i]);
    }

    RHO_ARRAY_CLEAREXT(&array, obj_destroy);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(&array) == 0);
}

static void 
test_heap_obj(struct rho_test *test)
{
    RHO_ARRAY_DECLARE(my_obj_array, struct obj *) *array;
    struct obj *p = NULL;
    size_t i = 0;
    size_t size = 0;

    RHO_ARRAY_ALLOC_INIT(array, struct obj *);

    p = obj_create(10); RHO_ARRAY_INSERT(array, 0, p);
    p = obj_create(20); RHO_ARRAY_INSERT(array, 1, p);
    p = obj_create(30); RHO_ARRAY_INSERT(array, 2, p);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(array) == 3);

    RHO_ARRAY_REMOVE(p, array, 1);
    RHO_TEST_ASSERT(p->bar == 20);
    obj_destroy(p);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(array) == 2);

    int expect[] = {10, 30};
    size = RHO_ARRAY_SIZE(array);
    for (i = 0; i < size; i++) {
        RHO_ARRAY_GET(p, array, i);
        RHO_TEST_ASSERT(p->bar == expect[i]);
    }

    RHO_ARRAY_CLEAREXT(array, obj_destroy);
    RHO_TEST_ASSERT(RHO_ARRAY_SIZE(array) == 0);
    rhoL_free(array);
}

static struct rho_test_suite_ops suite_ops = {
    .suite_init = NULL,
    .suite_fini = NULL,
    .test_init = NULL,
    .test_fini = NULL
};

static struct rho_test suite_tests[] = {
    RHO_TEST_DECL("auto int", test_auto_int),
    RHO_TEST_DECL("heap int", test_heap_int),
    RHO_TEST_DECL("auto obj", test_auto_obj),
    RHO_TEST_DECL("heap obj", test_heap_obj),
    RHO_TEST_SENTINEL
};

int
main(int argc, char *argv[])
{
    struct rho_test_suite suite;

    (void)argc;
    (void)argv;

    RHO_TEST_SUITE_INIT(&suite, "array", &suite_ops, suite_tests);
    rho_test_suite_run(&suite);

    return (0);
}
