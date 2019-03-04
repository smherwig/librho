#include <errno.h>
#include <stddef.h>

#if defined(RHO_PLAT_FREEBSD)
#define _WITH_GETLINE
#endif
#include <stdio.h>

#include "rho_log.h"

ssize_t
rho_term_getline(char **line, size_t *n)
{
    ssize_t ret = 0;

    ret = getline(line, n, stdin);
    if (ret == -1 && ferror(stdin))
        rho_errno_die(errno, "getline failed");

    return (ret);
}
