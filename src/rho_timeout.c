#include "rho_mem.h"
#include "rho_time.h"
#include "rho_timeout.h"

struct rho_timeout *
rho_timeout_create(struct timeval *timeout)
{
    struct rho_timeout *tm = NULL;

    tm = rhoL_zalloc(sizeof(*tm));
    rho_timeout_init(tm, timeout);

    return (tm);
}

struct rho_timeout *
rho_timeout_create_with_double(double timeout)
{
    struct rho_timeout *tm = NULL;

    tm = rhoL_zalloc(sizeof(*tm));
    rho_timeout_init_double(tm, timeout);

    return (tm);
}

void
rho_timeout_destroy(struct rho_timeout *tm)
{
    rhoL_free(tm);
}

void
rho_timeout_init(struct rho_timeout *tm, struct timeval *timeout)
{   
    tm->timeout = *timeout;
}

void
rho_timeout_init_double(struct rho_timeout *tm, double timeout)
{
    tm->timeout.tv_sec = timeout / 1; 
    tm->timeout.tv_usec = (suseconds_t)((timeout - (timeout / 1)) * 1.0e6);
}

void
rho_timeout_markstart(struct rho_timeout *tm)
{
    rhoL_gettimeofday(&tm->start, NULL);
    rho_timeval_add(&tm->start, &tm->timeout, &tm->end);
}

void
rho_timeout_timeleft(const struct rho_timeout *tm, struct timeval *left)
{
    int cmp = 0;
    struct timeval now;

    rhoL_gettimeofday(&now, NULL);
    cmp = rho_timeval_cmp(&tm->end, &now);
    if (cmp > 0) {
        rho_timeval_subtract(&tm->end, &now, left);
    } else {
        /* expired */
        left->tv_sec = 0;
        left->tv_usec = 0;
    }
}

double
rho_timeout_timeleft_double(const struct rho_timeout *tm)
{
    struct timeval left;

    rho_timeout_timeleft(tm, &left);
    return (rho_timeval_to_sec_double(&left));
}

/* by convention, a value of 0 means no timeout set */
void
rho_timeout_remove(struct rho_timeout *tm)
{
    struct timeval tv = { 0, 0 };

    rho_timeout_init(tm, &tv);
}
