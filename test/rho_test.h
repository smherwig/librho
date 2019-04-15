#ifndef _RHO_TEST_H_
#define _RHO_TEST_H_

#include "rho_decls.h"

RHO_DECLS_BEGIN

struct rho_test {
    const char *name;
    void (*fn) (struct rho_test *);
    int nfail;
    int nsuccess;
};

#define RHO_TEST_DECL(name, fn) \
    {name, fn, 0, 0}

#define RHO_TEST_SENTINEL \
    {NULL, NULL, 0, 0}


struct rho_test_suite_ops {
    int (*suite_init) (void);
    void (*suite_fini) (void);
    int (*test_init) (void);
    void (*test_fini) (void);
};

struct rho_test_suite {
    const char *name;
    struct rho_test_suite_ops *ops;
    struct rho_test *tests;
};

#define RHO_TEST_ASSERT(expr) \
   do { \
       if ((expr)) { \
           test->nsuccess++; \
       } else { \
            test->nfail++; \
            fprintf(stderr, "ASSERT FAIL %s : (%s) at %s:%d\n", \
                    test->name, #expr, __FILE__, __LINE__); \
       } \
   } while (0) 

#define RHO_TEST_SUITE_INIT(suite, _name, _ops, _tests) \
    do { \
        (suite)->name = _name; \
        (suite)->ops = _ops; \
        (suite)->tests = _tests; \
    } while (0)


void rho_test_suite_run(struct rho_test_suite *suite);

RHO_DECLS_END

#endif /* _RHO_TEST_H_ */
