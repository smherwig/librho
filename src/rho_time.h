#ifndef _RHO_TIME_H_
#define _RHO_TIME_H_

#include <sys/time.h>

#include <stdbool.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

void rhoL_gettimeofday(struct timeval *tv, struct timezone *tz);
double rhoL_gettimeofday_dobule(void);

/* like timerisset(3) */
#define rho_timeval_isset(ptv) ((ptv)->tv_sec || (ptv)->tv_usec)

void rho_timeval_add(const struct timeval *a, const struct timeval *b,
        struct timeval *sum);
void rho_timeval_subtract(const struct timeval *a, const struct timeval *b,
        struct timeval *diff);

int rho_timeval_cmp(const struct timeval *a, const struct timeval *b);

int rho_timeval_to_ms(const struct timeval *tv);
double rho_timeval_to_sec_double(const struct timeval *tv);

RHO_DECLS_END

#endif /* ! _RHO_TIME_H_ */
