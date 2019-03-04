#ifndef _RHO_FD_H_
#define _RHO_FD_H_

#include <sys/types.h>

#include <stdint.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

void rhoL_close(int fd);
void rhoL_dup2(int oldfd, int newfd);
off_t rhoL_lseek(int fd, off_t offset, int whence);

void rho_fd_setnonblocking(int fd);
void rho_fd_setblocking(int fd);

int rho_fd_readn(int fd, void *buffer, size_t n);
int rho_fd_writen(int fd, const void *buf, size_t n);

int rho_fd_readu8(int fd, uint8_t *out);
int rho_fd_readu16be(int fd, uint16_t *out);
int rho_fd_readu16le(int fd, uint16_t *out);
int rho_fd_readu32be(int fd, uint32_t *out);
int rho_fd_readu32le(int fd, uint32_t *out);
int rho_fd_readu64be(int fd, uint64_t *out);
int rho_fd_readu64le(int fd, uint64_t *out);


RHO_DECLS_END

#endif /* ! _ RHO_FD_H_ */
