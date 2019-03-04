#ifndef _RHO_SOCKET_H_
#define _RHO_SOCKET_H_

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <stdint.h>

#include "rho_decls.h"
#include "rho_buf.h"
#include "rho_timeout.h"

RHO_DECLS_BEGIN

/*
 * low-level wrappers
 */

int rhoL_socket(int domain, int type, int protocol);
void rhoL_bind(int fd, const struct sockaddr *addr, socklen_t alen);
void rhoL_listen(int fd, int backlog);
void rhoL_sendto(int fd, const void *buf, size_t len, int flags,
        const struct sockaddr *addr, socklen_t alen);

void rhoL_getsockname(int fd, struct sockaddr *addr, socklen_t *alen);
void rhoL_getsockname_str(int fd, char *ipstr, size_t ipstr_len, uint16_t *port);
void rhoL_getpeername(int fd, struct sockaddr *addr, socklen_t *alen);
void rhoL_getpeername_str(int fd, char *ipstr, size_t ipstr_len, uint16_t *port);

void rhoL_setsockopt_reuseaddr(int fd, int yesno);
void rhoL_setsockopt_ipv6only(int fd, int yesno);

int rho_sock_passfd(int sock, int fd);
int rho_sock_recvfd(int s);

/*
 * formatting wrappers
 */

int rhoL_inet_pton(int af, const char *src, void *dst);
const char * rhoL_inet_ntop(int af, const void *src, char *dst, socklen_t size);
const char * rhoL_inet_ntop_alloc(int af, const void *src);

/*
 * formatting helpers
 */
int rho_pack_sockaddr(const char *host_or_ip, const char *port,
        struct sockaddr_storage *ss, socklen_t *addrlen);

void rho_pack_sockaddr_in(const char *ip, const char *port,
        struct sockaddr_in *sa);

void rho_pack_sockaddr_in6(const char *ip, const char *port,
        struct sockaddr_in6 *sa6);

void rho_pack_sockaddr_un(uint8_t *name, size_t namelen,
        struct sockaddr_un *sun);

/*
 * high-level objects
 */
struct rho_ssl;

/* not opaque, as rho_ssl needs to manipulate struct members */
struct rho_sock {
    int fd;
    int af;     /* address family (e.g., AF_INET) */
    struct rho_sock_ops {
        ssize_t (*recv)     (struct rho_sock *, void *, size_t);
        ssize_t (*recvfrom) (struct rho_sock *, void *, size_t, 
                    struct sockaddr *, socklen_t *);
        ssize_t (*send)     (struct rho_sock *, const void *, size_t);
        ssize_t (*sendto) (struct rho_sock *, const void *, size_t, 
                    const struct sockaddr *, socklen_t);
        void    (*destroy)  (struct rho_sock *);
    } *ops;
    struct rho_timeout timeout;
    struct rho_ssl *ssl;
};

struct rho_sock * rho_sock_udp4_create(void);
struct rho_sock * rho_sock_udp4server_create(const char *address, short port);

struct rho_sock * rho_sock_udp6_create(void);

struct rho_sock *rho_sock_udp_from_fd(int fd);

struct rho_sock * rho_sock_tcp4_create(void);
struct rho_sock * rho_sock_tcp4server_create(const char *address, short port,
        int backlog);

struct rho_sock * rho_sock_tcp6_create(void);
struct rho_sock * rho_sock_tcp6server_create(const char *address, short port,
        int backlog);

struct rho_sock * rho_sock_tcp_from_fd(int fd);

struct rho_sock * rho_sock_unix_create(void);
struct rho_sock * rho_sock_unix_from_fd(int fd);
struct rho_sock * rho_sock_unixserver_create(uint8_t *name, size_t namelen,
        int backlog);

struct rho_sock * rho_sock_from_url(const char *url);

void rho_sock_setnonblocking(struct rho_sock *sock);
void rho_sock_setblocking(struct rho_sock *sock);

void rho_sock_settimeout(struct rho_sock *sock, struct timeval *tv);
void rho_sock_settimeout_sec(struct rho_sock *sock, int sec);

void rho_sock_bind(struct rho_sock *sock, const struct sockaddr *addr, 
        socklen_t alen);
void rho_sock_listen(struct rho_sock *sock, int backlog);
int rho_sock_accept(struct rho_sock *sock, struct sockaddr *addr,
    socklen_t *alen);
int rho_sock_connect(struct rho_sock *sock, const struct sockaddr *addr,
    socklen_t alen);
int rho_sock_connect_url(struct rho_sock *sock, const char *url);

ssize_t rho_sock_recv(struct rho_sock *sock, void *buf, size_t len);
ssize_t rho_sock_recv_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_precv_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_recvn(struct rho_sock *sock, void *buf, size_t len);
ssize_t rho_sock_recvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_precvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);

ssize_t rho_sock_recvfrom(struct rho_sock *sock, void *buf, size_t len,
        struct sockaddr *addr, socklen_t *alen);
ssize_t rho_sock_recvfrom_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len, struct sockaddr *addr, socklen_t *alen);

ssize_t rho_sock_send(struct rho_sock *sock, const void *buf, size_t len);
ssize_t rho_sock_send_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_psend_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_sendn(struct rho_sock *sock, const void *buf, size_t len);
ssize_t rho_sock_sendn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_psendn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);

ssize_t rho_sock_sendto(struct rho_sock *sock, const void *buf, size_t len,
       const struct sockaddr *addr, socklen_t alen);
ssize_t rho_sock_sendto_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len, const struct sockaddr *addr, socklen_t alen);

void rho_sock_destroy(struct rho_sock *sock);

RHO_DECLS_END

#endif /* _RHO_SOCKET_H_ */
