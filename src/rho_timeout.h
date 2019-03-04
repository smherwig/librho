#ifndef _RHO_TIMEOUT_H_
#define _RHO_TIMEOUT_H_

#include <sys/time.h>

#include "rho_decls.h"
#include "rho_time.h"

RHO_DECLS_BEGIN

/* 
 * not opaque so that can be use as automatic variable or 
 * struct member (which is how strut rho_sock uses it)
 */
struct rho_timeout {
    struct timeval timeout;
    struct timeval start;
    struct timeval end;     /* optimiziation; end = start + timeout */
};

struct rho_timeout * rho_timeout_create(struct timeval *timeout);
struct rho_timeout * rho_timeout_create_with_double(double timeout);
void rho_timeout_destroy(struct rho_timeout *tm);

void rho_timeout_init(struct rho_timeout *tm, struct timeval *timeout);
void rho_timeout_init_double(struct rho_timeout *tm, double timeout);

void rho_timeout_markstart(struct rho_timeout *tm);

void rho_timeout_timeleft(const struct rho_timeout *tm, struct timeval *left);
double rho_timeout_timeleft_double(const struct rho_timeout *tm);

void rho_timeout_remove(struct rho_timeout *tm);

#define rho_timeout_isset(ptm) (rho_timeval_isset(&(ptm)->timeout))

RHO_DECLS_END

#endif /* _RHO_TIMEOUT_H_ */
