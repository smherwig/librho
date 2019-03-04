#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "rho_endian.h"
#include "rho_fd.h"
#include "rho_log.h"

void
rhoL_close(int fd)
{
    int error = 0;

    error = close(fd);
    if (error == -1)
        rho_errno_die(errno, "close(fd=%d)", fd);
}

void
rhoL_dup2(int oldfd, int newfd)
{
    int fd;
    
    fd = dup2(oldfd, newfd);
    if (fd == -1)
        rho_errno_die(errno, "dup2(%d, %d)", oldfd, newfd);
    if (fd != newfd)
        rho_die("expected dup2(%d, %d) to return %d, but returned %d",
                oldfd, newfd, newfd, fd);
}

off_t
rhoL_lseek(int fd, off_t offset, int whence)
{
    off_t pos = 0;

    pos = lseek(fd, offset, whence);
    if (pos == -1)
        rho_errno_die(errno, "lseek(fd=%d, offset=%jd, whence=%d)",
                fd, (intmax_t)offset, whence);
    
    return (pos);
}

void
rho_fd_setnonblocking(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        rho_errno_die(errno, "fnctl");

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1)
        rho_errno_die(errno, "fnctl");

    return; 
}

void
rho_fd_setblocking(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        rho_errno_die(errno, "fnctl");

    flags &= (~(O_NONBLOCK));
    if (fcntl(fd, F_SETFL, flags) == -1)
        rho_errno_die(errno, "fnctl");

    return; 
}

/* TODO: shouldn't this be a ssize_t return value ? */
int
rho_fd_readn(int fd, void *buffer, size_t n)
{
    ssize_t nr = 0;
    size_t tot = 0;
    char *buf = NULL;

    buf = buffer;
    for (tot = 0; tot < n; ) {
        nr = read(fd, buf, n - tot);

        if (nr == 0)
            return (tot); /* EOF */

        if (nr == -1) {
            if (errno == EINTR)
                continue;
            else
                return (-1);
        }

        tot += nr;
        buf += nr;
    }

    return (tot);
}

/* TODO: shouldn't the return value be a ssize_t */
int
rho_fd_writen(int fd, const void *buffer, size_t n)
{
    ssize_t nw = 0;
    size_t tot = 0;
    const char *buf;

    buf = buffer;
    for (tot  = 0; tot < n; ) {
        nw = write(fd, buf, n - tot);
        if (nw <= 0) {
            if (nw == -1 && errno == EINTR)
                continue;
            else
                return (-1);
        }

        tot += nw;
        buf += nw;
    }

    return (tot);
}

int
rho_fd_readu8(int fd, uint8_t *out)
{
    return (rho_fd_readn(fd, out, sizeof(uint8_t)));
}

int
rho_fd_readu16be(int fd, uint16_t *out)
{
    int tot = 0;
    tot = rho_fd_readn(fd, out, sizeof(uint16_t));
    if (tot == sizeof(uint16_t))
        *out = be16toh(*out);
    return (tot);
}

int
rho_fd_readu16le(int fd, uint16_t *out)
{
    int tot = 0;
    tot = rho_fd_readn(fd, out, sizeof(uint16_t));
    if (tot == sizeof(uint16_t))
        *out = le16toh(*out);
    return (tot);
}

int
rho_fd_readu32be(int fd, uint32_t *out)
{
    int tot = 0;
    tot = rho_fd_readn(fd, out, sizeof(uint32_t));
    if (tot == sizeof(uint32_t))
        *out = be32toh(*out);
    return (tot);
}

int
rho_fd_readu32le(int fd, uint32_t *out)
{
    int tot = 0;
    tot = rho_fd_readn(fd, out, sizeof(uint32_t));
    if (tot == sizeof(uint32_t))
        *out = le32toh(*out);
    return (tot);
}

int
rho_fd_readu64be(int fd, uint64_t *out)
{
    int tot = 0;
    tot = rho_fd_readn(fd, out, sizeof(uint64_t));
    if (tot == sizeof(uint64_t))
        *out = be64toh(*out);
    return (tot);
}

int
rho_fd_readu64le(int fd, uint64_t *out)
{
    int tot = 0;
    tot = rho_fd_readn(fd, out, sizeof(uint64_t));
    if (tot == sizeof(uint64_t))
        *out = le32toh(*out);
    return (tot);
} 
