#include <stdio.h>

#include "rho_test.h"

void
rho_test_suite_run(struct rho_test_suite *suite)
{
    int error = 0;
    struct rho_test *test;
    int nfail = 0;
    int nsuccess = 0;
    int i =0;

    if (suite->ops->suite_init != NULL) {
        error = suite->ops->suite_init();
        if (error != 0) {
            fprintf(stderr, "failed to initialize suite %s\n", suite->name);
            goto done;
        }
    }

    for (i = 0; suite->tests[i].fn != NULL; i++) {
        if (suite->ops->test_init) {
            error = suite->ops->test_init();
            if (error != 0) {
                fprintf(stderr, "failed to initialize test %s\n", test->name);
                continue;
            }
        }

        test = &suite->tests[i];
        test->nfail = 0;
        test->nsuccess = 0;
        test->fn(test);
        fprintf(stderr, "TEST %s : %d / %d\n",
                test->name, test->nsuccess, test->nfail + test->nsuccess);

        if (suite->ops->test_fini)
            suite->ops->test_fini();

        nfail += test->nfail;
        nsuccess += test->nsuccess;
    }

    if (suite->ops->suite_init != NULL)
        suite->ops->suite_fini();

    fprintf(stderr, "SUITE %s : %d / %d\n",
            suite->name, nsuccess, nsuccess + nfail);

done:
    return;
}
