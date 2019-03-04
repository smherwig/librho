#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include "rho_daemon.h"
#include "rho_fd.h"
#include "rho_log.h"
#include "rho_path.h"

#define RHO_DAEMON_MAX_CLOSE    1024

/* TODO: allow user to change user/group
 * See the implementation of chroot(1).
 */
void
rho_daemon_chrootjail(const char *newroot)
{
    rhoL_chroot(newroot);
}

/* 
 * Based on implementation in 'Chapter 37: Daemons' of
 * 'The Linux Prgramming Interface' by Michael Kerrisk.
 */
void
rho_daemon_daemonize(const char *newwd, int flags)
{
    int fd = 0;
    int maxfd = 0;
    
    /* spawn child1; parent exits */
    switch (fork()) {
    case -1:    rho_errno_die(errno, "fork");
    case  0:    break;
    default:    _exit(EXIT_SUCCESS);
    }

    /* child1 becomes session leader */
    if (setsid() == -1)
        rho_errno_die(errno, "setsid");

    /* spawn child2; child1 exits; ensures child2 is not
     * session leader
     */
    switch (fork()) {
    case -1:    rho_errno_die(errno, "fork");
    case  0:    break;
    default:    _exit(EXIT_SUCCESS);
    }

    /* clear umask */
    if (flags & RHO_DAEMON_CLEAR_UMASK)
        umask(0);

    /* change working directory */
    if (newwd != NULL)
        rhoL_chdir(newwd);

    /* close all open files */
    if (flags & RHO_DAEMON_CLOSE_OPEN_FDS) {
        maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd == -1) {
            rho_warn("sysconf(_SC_OPEN_MAX) failed: can't get max open files; assuming %d",
                    RHO_DAEMON_MAX_CLOSE);
            maxfd = RHO_DAEMON_MAX_CLOSE;
        }
        for (fd = 0; fd < maxfd; fd++)
            (void)close(fd);
    }

    /* reopen stdin/stdout/stderr to /dev/null */
    if (flags & RHO_DAEMON_STD_FDS_TO_DEVNULL) {
        (void)close(STDIN_FILENO);

        fd = open("/dev/null", O_RDWR);
        if (fd == -1)
            rho_errno_die(errno, "open(\"dev/null\", O_RDWR)");
        if (fd != STDIN_FILENO) /* 'fd' should be 0 */
            rho_die("expected fd to be STDIN_FILENO, but is %d", fd);

        rhoL_dup2(STDIN_FILENO, STDOUT_FILENO);
        rhoL_dup2(STDIN_FILENO, STDERR_FILENO);
    }
    
    return;
}
