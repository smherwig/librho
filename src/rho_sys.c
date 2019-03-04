#include <sys/utsname.h>

#include <errno.h>

#include "rho_log.h"
#include "rho_sys.h"

void
rhoL_uname(struct utsname *name)
{
    if (uname(name) != 0)
        rho_errno_die(errno, "uname");
}
