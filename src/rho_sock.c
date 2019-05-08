#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "rho_buf.h"
#include "rho_fd.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_sock.h"
#include "rho_str.h"
#include "rho_url.h"
#include "rho_timeout.h"

/* The timeout code is based on LuaSocket 3.0:
 *
 * TODO: insert license
 */

/* on assertions:
 *  https://ptolemy.berkeley.edu/~johnr/tutorials/assertions.html
 */

/* ensures correct alignment */
union rho_sock_unixctrl {
    struct cmsghdr cmh;
    /* this is basically control[sizeof(struct cmghdr) + sizeof(int)] */
    char control[CMSG_SPACE(sizeof(int))];
}; 

static ssize_t rho_sock_udp_recv(struct rho_sock *sock, void *buf, size_t len);
static ssize_t rho_sock_udp_recvfrom(struct rho_sock *sock, void *buf, size_t len,
        struct sockaddr *addr, socklen_t *alen);
static ssize_t rho_sock_udp_send(struct rho_sock *sock, const void *buf, 
        size_t len);
static ssize_t rho_sock_udp_sendto(struct rho_sock *sock, const void *buf, size_t len,
        const struct sockaddr *addr, socklen_t alen);
static void rho_sock_udp_destroy(struct rho_sock *sock);

static struct rho_sock_ops rho_sock_udp_ops = {
    .recv       = rho_sock_udp_recv,
    .recvfrom   = rho_sock_udp_recvfrom,
    .send       = rho_sock_udp_send,
    .sendto     = rho_sock_udp_sendto,
    .destroy    = rho_sock_udp_destroy
};


static ssize_t rho_sock_stream_recv(struct rho_sock *sock, void *buf, 
        size_t len);
static ssize_t rho_sock_stream_send(struct rho_sock *sock, const void *buf,
        size_t len);
static void rho_sock_stream_destroy(struct rho_sock *sock);

static struct rho_sock * rho_sock_stream_create(void);
static struct rho_sock * rho_sock_udp_create(void);

static struct rho_sock_ops rho_sock_stream_ops = {
    .recv = rho_sock_stream_recv,
    .send = rho_sock_stream_send,
    .destroy = rho_sock_stream_destroy,
};

/*
 * LIBC WRAPPERS
 */

int
rhoL_socket(int domain, int type, int protocol)
{
    int fd = 0;

    fd = socket(domain, type, protocol);
    if (fd == -1)
        rho_errno_die(errno, "socket");

    return (fd);
}

void
rhoL_bind(int fd, const struct sockaddr *addr, socklen_t alen)
{
    int error = 0;

    error = bind(fd, addr, alen);
    if (error == -1)
        rho_errno_die(errno, "bind");
}

void
rhoL_listen(int fd, int backlog)
{
    int error = 0;

    error = listen(fd, backlog);
    if (error == -1)
        rho_errno_die(errno, "listen");
}

/* XXX: assumes blocking socket */
void
rhoL_sendto(int fd, const void *buf, size_t len, int flags,
        const struct sockaddr *addr, socklen_t alen)
{
    ssize_t ret = 0;

    ret = sendto(fd, buf, len, flags, addr, alen);
    if (ret == -1)
        rho_errno_die(errno, "sendto");
}

void
rhoL_getsockname(int fd, struct sockaddr *addr, socklen_t *alen)
{
    int error = 0;
    socklen_t olen = 0;

    olen = *alen;
    error = getsockname(fd, addr, alen);
    if (error == -1)
        rho_errno_die(errno, "getsockname");
    if (*alen > olen)
        rho_die("getsockname needs a buffer of %lu bytes (%lu given)",
                (unsigned long)(*alen), (unsigned long)olen);
}

/* ipstr_len should be INET6_ADDRSTRLEN */
void
rhoL_getsockname_str(int fd, char *ipstr, size_t ipstr_len, uint16_t *port)
{
    int error = 0;
    struct sockaddr_storage sas;
    socklen_t sas_len = sizeof(sas);

    rhoL_getsockname(fd, (struct sockaddr *)&sas, &sas_len);

    error = getnameinfo((struct sockaddr *)&sas, sas_len, ipstr, ipstr_len, NULL, 0,
            NI_NUMERICHOST);
    if (error)
        rho_die("getnameinfo failed: %s", gai_strerror(error));

    if (port != NULL) {
        switch (sas.ss_family) {
        case AF_INET:
            *port = ((struct sockaddr_in *)&sas)->sin_port;
            break;
        case AF_INET6:
            *port = ((struct sockaddr_in6 *)&sas)->sin6_port;
            break;
        default:
            rho_die("unknown address family: %d", sas.ss_family);
        }
    }
}

void
rhoL_getpeername(int fd, struct sockaddr *addr, socklen_t *alen)
{
    int error = 0;
    socklen_t olen = 0;

    olen = *alen;
    error = getpeername(fd, addr, alen);
    if (error == -1)
        rho_errno_die(errno, "getpeername");
    if (*alen > olen)
        rho_die("getpeername needs a buffer of %lu bytes (%lu given)",
                (unsigned long)(*alen), (unsigned long)olen);
}

/* ipstr_len should be INET6_ADDRSTRLEN */
void
rhoL_getpeername_str(int fd, char *ipstr, size_t ipstr_len, uint16_t *port)
{
    int error = 0;
    struct sockaddr_storage sas;
    socklen_t sas_len = sizeof(sas);

    rhoL_getpeername(fd, (struct sockaddr *)&sas, &sas_len);

    error = getnameinfo((struct sockaddr *)&sas, sas_len, ipstr, ipstr_len, NULL, 0,
            NI_NUMERICHOST);
    if (error)
        rho_die("getnameinfo failed: %s", gai_strerror(error));

    if (port != NULL) {
        switch (sas.ss_family) {
        case AF_INET:
            *port = ((struct sockaddr_in *)&sas)->sin_port;
            break;
        case AF_INET6:
            *port = ((struct sockaddr_in6 *)&sas)->sin6_port;
            break;
        default:
            rho_die("unknown address family: %d", sas.ss_family);
        }
    }
}

/*
 * SOCKET OPTION CONVENIENCE FUNCTIONS
 */

void
rhoL_setsockopt_reuseaddr(int fd, int yesno)
{
    int error = 0;

    error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yesno, sizeof(int));
    if (error == -1)
        rho_errno_die(errno, "setsockopt(SO_REUSEADDR, %d)", yesno);
}

void
rhoL_setsockopt_ipv6only(int fd, int yesno)
{
    int error = 0;

    error = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yesno, sizeof(int));
    if (error == -1)
        rho_errno_die(errno, "setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, %d)", yesno);
}

void
rhoL_setsockopt_disable_nagle(int fd)
{
    int error = 0;
    int flag = 1;

    error = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    if (error == -1)
        rho_errno_die(errno, "setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)");
}

/*
 * UNIX DOMAIN FD PASSING (man cmsg(3)
 */

int
rho_sock_passfd(int sock, int fd) 
{
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmhp;
    char b = '\0';
    union rho_sock_unixctrl control_un;

    rho_memzero(&msg, sizeof(msg));

    /* on Linux, must transmit at least 1 byte of real data in order to send
     * ancillary data
     */
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    iov.iov_base = &b;
    iov.iov_len = 1;

    /* describe ancillary data to send (i.e., the socket  descriptor)
     * with the message.
     */
    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);

    /* basically a cast:  (struct cmshdr *)&msg->msg_control */
    cmhp = CMSG_FIRSTHDR(&msg);
    cmhp->cmsg_len = CMSG_LEN(sizeof(int));
    cmhp->cmsg_level = SOL_SOCKET;
    cmhp->cmsg_type = SCM_RIGHTS;
    *((int *)CMSG_DATA(cmhp)) = fd;

    return (sendmsg(sock, &msg, 0));
}

int
rho_sock_recvfd(int s)
{
    struct msghdr msg;
    struct iovec iov;
    char b = '\0';
    int fd = -1;
    ssize_t nr = 0;
    union rho_sock_unixctrl control_un;
    struct cmsghdr *cmhp;

    control_un.cmh.cmsg_len = CMSG_LEN(sizeof(int));
    control_un.cmh.cmsg_level = SOL_SOCKET;
    control_un.cmh.cmsg_type = SCM_RIGHTS;

    msg.msg_control = control_un.control;
    msg.msg_controllen = sizeof(control_un.control);
     
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    iov.iov_base = &b;
    iov.iov_len = 1;

    nr = recvmsg(s, &msg, 0);
    if (nr == -1)
        goto fail;

    cmhp = CMSG_FIRSTHDR(&msg);
    if (cmhp == NULL || cmhp->cmsg_len != CMSG_LEN(sizeof(int))) {
        goto fail;
    }

    if (cmhp->cmsg_level != SOL_SOCKET) {
        goto fail;
    }

    if (cmhp->cmsg_type != SCM_RIGHTS) {
        goto fail;
    }

    fd = *((int *)CMSG_DATA(cmhp));

fail:
    return (fd);
}

/*
 * LIBC ADDRESS FORMATTING/CONVERTING WRAPPERS
 */

/* XXX: allow return of 0 (not parseble)*/
int
rhoL_inet_pton(int af, const char *src, void *dst)
{
    int ret = 0;

    ret = inet_pton(af, src, dst);
    if (ret == 0)
        rho_die("address \"%s\" is not parseable", src);
    if (ret == -1)
        rho_errno_die(errno, "error occurred while parsing address \"%s\"", src);

    return (ret);
}

const char *
rhoL_inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
    const char *p = NULL;

    p = inet_ntop(af, src, dst, size);
    if (p == NULL)
        rho_errno_die(errno, "inet_ntop(af=%d, size=%lu)", af, (unsigned long)size);
    return (p);
}

const char *
rhoL_inet_ntop_alloc(int af, const void *src)
{
    const char *p = NULL;
    char *dst = rhoL_zalloc(INET6_ADDRSTRLEN);

    p = inet_ntop(af, src, dst, INET6_ADDRSTRLEN);
    if (p == NULL)
        rho_errno_die(errno, "inet_ntop(af=%d, size=%d)", af,
                INET6_ADDRSTRLEN);
    return (p);
}

/*
 * FORMATTING HELPS
 */

/*
 * https://stackoverflow.com/questions/42178179/will-casting-around-sockaddr-storage-and-sockaddr-in-break-strict-aliasing/42190913
 * https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
 *
 * return 0 on success, -1 on error.
 */
int
rho_pack_sockaddr(const char *host_or_ip, const char *port,
        struct sockaddr_storage *ss, socklen_t *addrlen)
{
    int error = 0;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it = NULL;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;

    rho_memzero(&hints, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_NUMERICSERV;

    error = getaddrinfo(host_or_ip, port, &hints, &res); 
    if (error != 0)  {
        rho_warn("getnameinfo(\"%s\", \"%s\") failed: %s",
                host_or_ip, port, gai_strerror(error));
        error = -1;
        goto done;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        switch (it->ai_family) {
        case AF_INET:
            sin = (struct sockaddr_in *)ss;
            *sin = *((struct sockaddr_in *)it->ai_addr);
            *addrlen = it->ai_addrlen;
            goto done;
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *)ss;
            *sin6 = *((struct sockaddr_in6 *)it->ai_addr);
            *addrlen = it->ai_addrlen;
            goto done;
        default:
            rho_die("unknown address family: %d", it->ai_family);
        }
    }

done:
    if (res != NULL)
        freeaddrinfo(res);      
    return (error);
}

void
rho_pack_sockaddr_in(const char *ip, const char *port, struct sockaddr_in *sa)
{
    sa->sin_family = AF_INET;
    sa->sin_port = htons(rho_str_touint16(port, 10));
    rhoL_inet_pton(AF_INET, ip, &sa->sin_addr);
}

void
rho_pack_sockaddr_in6(const char *ip, const char *port, struct sockaddr_in6 *sa6)
{
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(rho_str_touint16(port, 10));
    rhoL_inet_pton(AF_INET6, ip, &sa6->sin6_addr);
}

void
rho_pack_sockaddr_un(uint8_t *name, size_t namelen, struct sockaddr_un *sun)
{
    /* fancy way of saying len >= sizeof(sun->sun_path)) */
    if (namelen > (sizeof(struct sockaddr_un) - sizeof(sa_family_t)))
        rho_die("unix domain socket path is too large");

    rho_memzero(sun, sizeof(struct sockaddr_un));
    sun->sun_family = AF_UNIX;
    /* FIXME: could overlfow sun_path */
    memcpy(sun->sun_path, name, namelen);
}

/*
 * HIGH-LEVEL: UDP SOCKET OBJECT (struct rho_udp)
 */

/* common for tcp and unix domain sockets */
static struct rho_sock *
rho_sock_stream_create(void)
{
    struct rho_sock *sock = rhoL_zalloc(sizeof(*sock));
    sock->ops = &rho_sock_stream_ops;
    return (sock);
}

static struct rho_sock *
rho_sock_udp_create(void)
{
    struct rho_sock *sock = rhoL_zalloc(sizeof(*sock));
    sock->ops = &rho_sock_udp_ops;
    return (sock);
}

/* 
 * returns 0 on success, -1 on error (and sets errno)
 *
 * are ETIMEDOUT and EDCONNREFUSED the correct values to return? 
 */
static int
rho_sock_waitfd(struct rho_sock *sock, int pollflags)
{
    int ret = 0;
    struct pollfd pfd;
    struct timeval tv;
    int ms = 0;

    pfd.fd = sock->fd;
    pfd.events = pollflags;
    pfd.revents = 0;

    /* optimize timeout == 0 case */
    if (!rho_timeout_isset(&sock->timeout)) {
        errno = ETIMEDOUT;
        ret = -1;
        goto done;
    }
    
    do {
        rho_timeout_timeleft(&sock->timeout, &tv);
        ms = rho_timeval_to_ms(&tv);
        ret = poll(&pfd, 1, ms);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1)
        goto done;

    if (ret == 0) {
        errno = ETIMEDOUT;
        ret = -1;
        goto done;
    }

    /*  
     *  XXX: I don't undertand this case; luasocket implies that this case
     *  means that the connection was closed
     */
    if ((pollflags == (POLLIN|POLLOUT)) && (pfd.revents & (POLLIN|POLLERR))) {
        ret = -1;
        errno = ECONNREFUSED;
        goto done;
    }

done:
    return (ret);
}

static void
rho_sock_trybind(int fd, const char *address, short port, struct addrinfo *bindhints)
{
    int error = 0;
    struct addrinfo *iter = NULL;
    struct addrinfo *resolved = NULL;
    char portstr[6] = { 0 };

    RHO_ASSERT(fd > 0);

    (void)snprintf(portstr, sizeof(portstr), "%d", port);

    error = getaddrinfo(address, portstr, bindhints, &resolved);
    if (error)
        rho_die("getaddinfo(address=\"%s\", port=\"%s\")", address, portstr);

    for (iter = resolved; iter != NULL; iter = iter->ai_next) {
        error = bind(fd, (struct sockaddr *)iter->ai_addr, iter->ai_addrlen);
        if (error == -1)
            rho_errno_warn(errno, "bind");
        else
            break;
    }

    freeaddrinfo(resolved);
    if (error != 0)
        rho_die("unabled to bind");
}

/*
 * CONSTRUCTORS
 */

struct rho_sock *
rho_sock_udp4_create(void)
{
    struct rho_sock *sock = rho_sock_udp_create();
    sock->fd = rhoL_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    return (sock);
}

/* 
 * for INADDR_ANY, pass NULL as the address parameter
 */
struct rho_sock *
rho_sock_udp4server_create(const char *address, short port)
{
    struct rho_sock *sock = NULL;
    struct addrinfo bindhints;

    sock = rho_sock_udp4_create();
    rhoL_setsockopt_reuseaddr(sock->fd, 1);

    rho_memzero(&bindhints, sizeof(bindhints));
    bindhints.ai_family = PF_INET;
    bindhints.ai_socktype = SOCK_DGRAM;
    bindhints.ai_protocol = IPPROTO_UDP;
    bindhints.ai_flags = AI_PASSIVE;
    rho_sock_trybind(sock->fd, address, port, &bindhints); 

    return (sock);
}

struct rho_sock *
rho_sock_udp6_create(void)
{
    struct rho_sock *sock = rho_sock_udp_create();
    sock->fd = rhoL_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    rhoL_setsockopt_ipv6only(sock->fd, 1);
    return (sock);
}

struct rho_sock *
rho_sock_udp_from_fd(int fd)
{
    struct rho_sock *sock = NULL;
    struct sockaddr_storage ss;
    socklen_t alen = 0;
    int af = 0;

    sock = rho_sock_udp_create();
    sock->fd = fd;

    alen = sizeof(ss);
    rho_memzero(&ss, alen);
    rhoL_getsockname(fd, (struct sockaddr *)&ss, &alen);
    af = ss.ss_family;
    if ((af != AF_INET) && (af != AF_INET6))
        rho_die("can't use  a socket fd with address family %d to create a TCP socket", af);
    if (af == AF_INET6)
        rhoL_setsockopt_ipv6only(fd, 1);
    sock->af = af;

    return (sock);
}

struct rho_sock *
rho_sock_tcp4_create(void)
{
    struct rho_sock *sock = rho_sock_stream_create();
    sock->af = AF_INET;
    sock->fd = rhoL_socket(AF_INET, SOCK_STREAM, 0);
    return (sock);
}

/* 
 * for INADDR_ANY, pass NULL as the address parameter
 */
struct rho_sock *
rho_sock_tcp4server_create(const char *address, short port, int backlog)
{
    struct rho_sock *sock = NULL;
    struct addrinfo bindhints;

    sock = rho_sock_tcp4_create();
    rhoL_setsockopt_reuseaddr(sock->fd, 1);

    rho_memzero(&bindhints, sizeof(bindhints));
    bindhints.ai_family = PF_INET;
    bindhints.ai_socktype = SOCK_STREAM;
    bindhints.ai_protocol = IPPROTO_TCP;
    bindhints.ai_flags = AI_PASSIVE;

    rho_sock_trybind(sock->fd, address, port, &bindhints); 
    rhoL_listen(sock->fd, backlog);

    return (sock);
}

struct rho_sock *
rho_sock_tcp6_create(void)
{
    struct rho_sock *sock = rho_sock_stream_create();
    sock->af = AF_INET6;
    sock->fd = rhoL_socket(AF_INET6, SOCK_STREAM, 0);
    rhoL_setsockopt_ipv6only(sock->fd, 1);
    return (sock);
}

struct rho_sock *
rho_sock_tcp_from_fd(int fd)
{
    struct rho_sock *sock = NULL;
    struct sockaddr_storage ss;
    socklen_t alen = 0;
    int af = 0;
    
    sock = rho_sock_stream_create();
    sock->fd = fd;

    alen = sizeof(ss);
    rho_memzero(&ss, alen);
    rhoL_getsockname(fd, (struct sockaddr *)&ss, &alen);
    af = ss.ss_family;
    if ((af != AF_INET) && (af != AF_INET6))
        rho_die("can't use a socket fd with address family %d to create a TCP socket", af);
    if (af == AF_INET6)
        rhoL_setsockopt_ipv6only(fd, 1);
    sock->af = af;
    return (sock);
}

struct rho_sock *
rho_sock_tcp6server_create(const char *address, short port, int backlog)
{
    struct rho_sock *sock = NULL;
    struct addrinfo bindhints;

    sock = rho_sock_tcp6_create();
    rhoL_setsockopt_reuseaddr(sock->fd, 1);

    rho_memzero(&bindhints, sizeof(bindhints));
    bindhints.ai_family = PF_INET6;
    bindhints.ai_socktype = SOCK_STREAM;
    bindhints.ai_protocol = IPPROTO_TCP;
    bindhints.ai_flags = AI_PASSIVE;

    rho_sock_trybind(sock->fd, address, port, &bindhints); 
    rhoL_listen(sock->fd, backlog);

    return (sock);
}

struct rho_sock *
rho_sock_unix_create(void)
{
    struct rho_sock *sock = rho_sock_stream_create();
    sock->af = AF_UNIX;
    sock->fd = rhoL_socket(AF_UNIX, SOCK_STREAM, 0);
    return (sock);
}

struct rho_sock *
rho_sock_unix_from_fd(int fd)
{
    struct rho_sock *sock = rho_sock_stream_create();
    sock->af = AF_UNIX;

    /* TODO: make sure fd is of type UNIX: what does getsockname
     * return for a UNIX domain socket?
     */
    sock->fd = fd;
    return (sock);
}

/*
 * To support anonymous unix sockets, path is not assumed to be a string.
 * XXX: If name is string, sould namelen include the nul byte?
 */
struct rho_sock *
rho_sock_unixserver_create(uint8_t *name, size_t namelen, int backlog)
{
    struct rho_sock *sock = NULL;
    struct sockaddr_un sun;

    RHO_ASSERT(name != NULL);
    RHO_ASSERT(backlog > 0);

    RHO_TRACE_ENTER("name=%s%s, namelen=%zu, backlog=%d",
            name[0] == '\0' ? "\x00" : "",
            name[0] == '\0' ? name + 1 : name,
            namelen, backlog);

    rho_pack_sockaddr_un(name, namelen, &sun);
    sock = rho_sock_stream_create();
    sock->af = AF_UNIX;
    sock->fd = rhoL_socket(AF_UNIX, SOCK_STREAM, 0);
    rhoL_bind(sock->fd, (struct sockaddr *)&sun, sizeof(struct sockaddr_un));
    rhoL_listen(sock->fd, backlog);
        
    RHO_TRACE_EXIT("fd=%d", sock->fd);
    return (sock);
}

/* XXX: should we default to creating a tcp4 socket if we can't
 * determine the scheme.  Should we do DNS A and AAAA queries
 * to decide which type of socket to create?
 */
struct rho_sock *
rho_sock_from_url(const char *url)
{
    struct rho_sock *sock = NULL;
    struct rho_url *rurl = NULL;
    const char *scheme = NULL;

    rurl = rho_url_parse(url); 
    if (rurl == NULL)
        goto default_ctor;

    scheme = rurl->scheme;
    if (scheme == NULL)
        goto default_ctor;

    if (rho_str_equal_ci(scheme, "tcp") || rho_str_equal_ci(scheme, "tcp4"))
        sock = rho_sock_tcp4_create();
    else if (rho_str_equal_ci(scheme, "tcp6"))
        sock = rho_sock_tcp6_create();
    else if (rho_str_equal_ci(scheme, "unix"))
        sock = rho_sock_unix_create();
    else if (rho_str_equal_ci(scheme, "udp") || rho_str_equal_ci(scheme, "upd4"))
        sock = rho_sock_udp4_create();
    else if (rho_str_equal_ci(scheme, "udp6"))
        sock = rho_sock_udp6_create();
    else
        goto default_ctor;

    goto done;

default_ctor:
    rho_warn("can't determine protocol for url \"%s\"; defaulting to creating tcp4 socket", url);
    sock = rho_sock_tcp4_create();
done:
    if (rurl != NULL)
        rho_url_destroy(rurl);
    return (sock);
}

/*
 * IMPLEMENTATION-INDEPENDENT SOCK OPS
 */

void
rho_sock_setnonblocking(struct rho_sock *sock)
{
    RHO_ASSERT(sock != NULL);
    rho_fd_setnonblocking(sock->fd);
}

void
rho_sock_setblocking(struct rho_sock *sock)
{
    RHO_ASSERT(sock != NULL);

    rho_fd_setblocking(sock->fd);
    rho_timeout_remove(&sock->timeout);
}

void
rho_sock_settimeout(struct rho_sock *sock, struct timeval *tv)
{
    rho_sock_setnonblocking(sock);
    rho_timeout_init(&sock->timeout, tv);
}

void
rho_sock_settimeout_sec(struct rho_sock *sock, int sec)
{
    struct timeval tv;
    rho_memzero(&tv, sizeof(tv));
    tv.tv_sec = sec;
    rho_sock_setnonblocking(sock);
    rho_timeout_init(&sock->timeout, &tv);
}

void 
rho_sock_bind(struct rho_sock *sock, const struct sockaddr *addr, 
        socklen_t alen)
{
    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(addr != NULL);

    rhoL_bind(sock->fd, addr, alen);
}

void
rho_sock_listen(struct rho_sock *sock, int backlog)
{
    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(backlog > 0);

    rhoL_listen(sock->fd, backlog);
}

int
rho_sock_accept(struct rho_sock *sock, struct sockaddr *addr,
    socklen_t *alen)
{
    int fd = 0;

    RHO_ASSERT(sock != NULL);

    /* TODO: check if has timeout */
    fd = accept(sock->fd, addr, alen);

    return (fd);
}

int 
rho_sock_connect(struct rho_sock *sock, const struct sockaddr *addr,
    socklen_t alen)
{
    int ret = 0;

    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(addr != NULL);

    if (rho_timeout_isset(&sock->timeout))
        rho_timeout_markstart(&sock->timeout);

    /* call connect until done or failed without being interrupted */
    do {
        ret = connect(sock->fd, addr, alen);
        if (ret == 0)
            goto done;
    } while (errno == EINTR);

    /* if connection failed immediately, return error code */
    if (errno != EINPROGRESS && errno != EAGAIN)
        goto done;

    if (!rho_timeout_isset(&sock->timeout)) {
        /* no timeout set; (errno is EINPROGRESS or EGAIN) */
        goto done;
    } else {
        /* timeout set; keep trying */
        ret = rho_sock_waitfd(sock, POLLIN|POLLOUT);
    }

done:
    return (ret);
}

int
rho_sock_connect_url(struct rho_sock *sock, const char *url)
{
    struct rho_url *purl = NULL;
    const char *scheme = NULL;
    struct sockaddr_storage ss;
    socklen_t alen = 0;

    purl = rho_url_parse(url);
    scheme = purl->scheme;

    rho_memzero(&ss, sizeof(ss));
    if (rho_str_equal_ci(scheme, "tcp") || rho_str_equal_ci(scheme, "tcp4") ||
            rho_str_equal_ci(scheme, "udp") || rho_str_equal_ci(scheme, "upd4")) {
        rho_pack_sockaddr_in(purl->host, purl->port, (struct sockaddr_in *)&ss);
        alen = sizeof(struct sockaddr_in);
    } else if (rho_str_equal_ci(scheme, "tcp6") || rho_str_equal_ci(scheme, "udp6")) {
        rho_pack_sockaddr_in6(purl->host, purl->port, (struct sockaddr_in6 *)&ss);
        alen = sizeof(struct sockaddr_in6);
    } else if (rho_str_equal_ci(scheme, "unix")) {
        rho_pack_sockaddr_un((uint8_t *)purl->path, strlen(purl->path), (struct sockaddr_un *)&ss);
        alen = sizeof(struct sockaddr_un);
    } else  {
        /* TODO:
         * Need to get url's scheme, host, and port.  If port is not provided,
         * use scheme's default port, if defined.  If host is a domainname, must
         * do a DNS lookup.  The lookup should be for an A record if the
         * socket fd is for TCP4/UDP4, and for an AAAA record if the socket
         * fd is for TCP6/UDP6.
         */ 
    }

    return (rho_sock_connect(sock, (struct sockaddr *)&ss, alen));
}

ssize_t
rho_sock_recv(struct rho_sock *sock, void *buf, size_t len)
{
    ssize_t n = 0;

    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(sock->ops != NULL);
    RHO_ASSERT(sock->ops->recv != NULL);

    if (rho_timeout_isset(&sock->timeout))
        rho_timeout_markstart(&sock->timeout);

    while (1) {
        n = sock->ops->recv(sock, buf, len);
        if (n >= 0)
            goto done;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN)
            goto done;
    
        if (!rho_timeout_isset(&sock->timeout)) {
            goto done;
        } else {
            if (rho_sock_waitfd(sock, POLLIN) == -1)
                goto done;
        }
    }

done:
    return (n);
}

ssize_t
rho_sock_recv_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    ssize_t n = 0;
    n = rho_sock_precv_buf(sock, buf, len);
    if (n > 0)
        rho_buf_seek(buf, n, SEEK_CUR);
    return (n);
}

ssize_t
rho_sock_precv_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    void *b = NULL;
    rho_buf_ensure(buf, len);
    b = rho_buf_raw(buf, 0, SEEK_CUR);
    return (rho_sock_recv(sock, b, len));
}

ssize_t 
rho_sock_recvn(struct rho_sock *sock, void *buf, size_t n)
{
    ssize_t nr = 0;
    size_t tot = 0;
    char *p = NULL;

    p = buf;
    for (tot = 0; tot < n; ) {
        nr = rho_sock_recv(sock, p, n - tot);

        if (nr == 0)
            return (tot); /* EOF */

        if (nr == -1) {
            if (errno == EINTR)
                continue;
            else
                return (-1);
        }

        tot += nr;
        p += nr;
    }

    return (tot);
}

ssize_t
rho_sock_recvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t n)
{
    ssize_t got = 0;
    got = rho_sock_precvn_buf(sock, buf, n);
    if (got > 0)
        rho_buf_seek(buf, got, SEEK_CUR);
    return (got);
}

ssize_t
rho_sock_precvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t n)
{
    ssize_t got = 0;
    char *p = NULL;

    rho_buf_ensure(buf, n);
    p = rho_buf_raw(buf, 0, SEEK_CUR);
    got = rho_sock_recvn(sock, p, n);
    if (got > 0) {
        if ((buf->pos + ((size_t)got)) > buf->len)
            buf->len = buf->pos + (size_t)got;
    }
    return (got);

}

ssize_t
rho_sock_recvfrom(struct rho_sock *sock, void *buf, size_t len,
        struct sockaddr *addr, socklen_t *alen)
{
    ssize_t n = 0;

    while (1) {
        n = sock->ops->recvfrom(sock, buf, len, addr, alen);
        if (n >= 0)
            goto done;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN)
            goto done;

        if (!rho_timeout_isset(&sock->timeout)) {
            goto done;
        } else {
            if (rho_sock_waitfd(sock, POLLIN) == -1)
                goto done;
        }
    }

done:
    return (n);
}

ssize_t
rho_sock_recvfrom_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len,
        struct sockaddr *addr, socklen_t *alen)
{
    ssize_t n = 0;
    void *b = NULL;

    rho_buf_ensure(buf, len);
    b = rho_buf_raw(buf, 0, SEEK_CUR);
    n = rho_sock_recvfrom(sock, b, len, addr, alen);
    if (n == -1)
        goto done;
    rho_buf_seek(buf, n, SEEK_CUR);

done:
    return (n);
}

ssize_t
rho_sock_send(struct rho_sock *sock, const void *buf, size_t len)
{
    ssize_t n = 0;

    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(buf != NULL);
    RHO_ASSERT(sock->ops != NULL);
    RHO_ASSERT(sock->ops->send != NULL);

    if (rho_timeout_isset(&sock->timeout))
        rho_timeout_markstart(&sock->timeout);

    while (1) {
        n = sock->ops->send(sock, buf, len);
        if (n >= 0)
            goto done;
        if (errno  == EINTR)
            continue;
        if (errno != EAGAIN)
            goto done;

        if (!rho_timeout_isset(&sock->timeout)) {
            goto done;
        } else {
            if (rho_sock_waitfd(sock, POLLOUT) == -1)
                goto done;
        }
    }

done:
    return (n);
}

ssize_t
rho_sock_send_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    ssize_t n = rho_sock_psend_buf(sock, buf, len);
    if (n > 0)
        rho_buf_seek(buf, n, SEEK_CUR);
    return (n);
}
ssize_t
rho_sock_psend_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    void *b = rho_buf_raw(buf, 0, SEEK_CUR);
    return (rho_sock_send(sock, b, len));
}

/*
 * Note that the semantics are similar to Python's socket.sendall;
 * namely, in the case of an error, the function does not return
 * how many bytes were sent, but simply returns -1.
 */
ssize_t
rho_sock_sendn(struct rho_sock *sock, const void *buf, size_t n)
{
    ssize_t nw = 0;
    size_t tot = 0;
    const char *p = NULL;

    p = buf;
    for (tot = 0; tot < n; tot += nw, p += nw) {
        nw = rho_sock_send(sock, p, n - tot);
        if (nw == -1)
            return (-1);
    }

    return (tot);
}

ssize_t
rho_sock_sendn_buf(struct rho_sock *sock, struct rho_buf *buf, size_t n)
{
    ssize_t put = 0;
    put = rho_sock_psendn_buf(sock, buf, n);
    if (put > 0)
        rho_buf_seek(buf, put, SEEK_CUR);
    return (put);
}

ssize_t
rho_sock_psendn_buf(struct rho_sock *sock, struct rho_buf *buf, size_t n)
{
    const char *p = rho_buf_raw(buf, 0, SEEK_CUR);
    return (rho_sock_sendn(sock, p, n));
}

ssize_t
rho_sock_sendto(struct rho_sock *sock, const void *buf, size_t len,
       const struct sockaddr *addr, socklen_t alen) 
{
    ssize_t n = 0;

    if (rho_timeout_isset(&sock->timeout))
        rho_timeout_markstart(&sock->timeout);

    while (1) {
        n = sock->ops->sendto(sock, buf, len, addr, alen);
        if (n >= 0)
            goto done;
        if (errno  == EINTR)
            continue;
        if (errno != EAGAIN)
            goto done;

        if (!rho_timeout_isset(&sock->timeout)) {
            goto done;
        } else {
            if (rho_sock_waitfd(sock, POLLOUT) == -1)
                goto done;
        }
    }

done:
    return (n);
}

ssize_t
rho_sock_sendto_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len,
       const struct sockaddr *addr, socklen_t alen) 
{
    void *b = NULL;
    ssize_t n = 0;

    b = rho_buf_raw(buf, 0, SEEK_CUR);
    n = rho_sock_sendto(sock, b, len, addr, alen);
    if (n == -1)
        goto done;
    rho_buf_seek(buf, n, SEEK_CUR);

done:
    return (n);
}

void
rho_sock_destroy(struct rho_sock *sock)
{
    RHO_ASSERT(sock != NULL);
    RHO_ASSERT(sock->ops != NULL);
    RHO_ASSERT(sock->ops->destroy != NULL);

    rho_sock_setblocking(sock);
    sock->ops->destroy(sock);
}

/*
 * UDP/UDP6 OPS
 */

static ssize_t
rho_sock_udp_recv(struct rho_sock *sock, void *buf, size_t len)
{
    return (recv(sock->fd, buf, len, 0));
}

ssize_t
rho_sock_udp_recvfrom(struct rho_sock *sock, void *buf, size_t len,
        struct sockaddr *addr, socklen_t *alen)
{
    return (recvfrom(sock->fd, buf, len, 0, addr, alen));
}

static ssize_t
rho_sock_udp_send(struct rho_sock *sock, const void *buf, size_t len)
{
    return (send(sock->fd, buf, len, 0));
}

static ssize_t
rho_sock_udp_sendto(struct rho_sock *sock, const void *buf, size_t len,
        const struct sockaddr *addr, socklen_t alen)
{
    return (sendto(sock->fd, buf, len, 0, addr, alen));
}

static void
rho_sock_udp_destroy(struct rho_sock *sock)
{
    if (sock->fd > 0)
        rhoL_close(sock->fd);
    rhoL_free(sock);
}

/*
 * TCP/TCP6/UNIX-SPECIFIC OPS
 */

static ssize_t
rho_sock_stream_recv(struct rho_sock *sock, void *buf, size_t len)
{
    return (recv(sock->fd, buf, len, 0));
}

static ssize_t
rho_sock_stream_send(struct rho_sock *sock, const void *buf, size_t len)
{
    return (send(sock->fd, buf, len, 0));
}

static void
rho_sock_stream_destroy(struct rho_sock *sock)
{
    if (sock->fd > 0)
        rhoL_close(sock->fd);
    rhoL_free(sock);
}
