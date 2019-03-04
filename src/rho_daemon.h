#ifndef _RHO_DAEMON_H_
#define _RHO_DAEMON_H_

#include "rho_decls.h"

RHO_DECLS_BEGIN

/* flags for rho_daemon_daemonize */
#define RHO_DAEMON_CLEAR_UMASK          (1<<0)
#define RHO_DAEMON_CLOSE_OPEN_FDS       (1<<1)
#define RHO_DAEMON_STD_FDS_TO_DEVNULL   (1<<2)

/* TODO: allow user to change user/group */
void rho_daemon_chrootjail(const char *newroot);
void rho_daemon_daemonize(const char *newwd, int flags);

/*
 * TODO:
 *  path = rho_daemon_createpidfile(TEMPLATE);
 */

RHO_DECLS_END

#endif /* _RHO_DAEMON_H_ */
