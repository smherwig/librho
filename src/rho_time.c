#include <sys/time.h>

#include <stdbool.h>
#include <errno.h>

#include "rho_log.h"
#include "rho_time.h"

#define RHO_USEC_IN_SEC 1000000

void
rhoL_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    int error = 0;
    error = gettimeofday(tv, tz);
    if (error == -1)
        rho_errno_die(errno, "gettimeofday failed");
}

double
rhoL_gettimeofday_double(void)
{
    struct timeval tv;

    rhoL_gettimeofday(&tv, NULL);
    return (rho_timeval_to_sec_double(&tv));
}

/* like timeradd(3) */
void
rho_timeval_add(const struct timeval *a, const struct timeval *b,
        struct timeval *sum)
{
    suseconds_t usec = 0;

    /* TODO: check for overflow */
    sum->tv_sec = a->tv_sec + b->tv_sec;
    usec = a->tv_usec + b->tv_usec;
    if (usec > RHO_USEC_IN_SEC) {
        sum->tv_sec += 1;
        sum->tv_usec = usec - RHO_USEC_IN_SEC;
    } else {
        sum->tv_usec = usec;
    }
}

/* like timersub(3): we assume time_t and susecond_t are signed */
void
rho_timeval_subtract(const struct timeval *a, const struct timeval *b,
        struct timeval *diff)
{
    diff->tv_sec = a->tv_sec - b->tv_sec;
    if (a->tv_usec > b->tv_usec) {
        diff->tv_usec = a->tv_usec - b->tv_usec;
    } else {
        diff->tv_sec--;
        diff->tv_usec = 1000000 - b->tv_usec + a->tv_usec;
    }
}

/* returns 1 if a > b; 0 if equal, -1 if a < b 
 *
 * like timecmp(3), but slightly different interface
 */
int
rho_timeval_cmp(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec > b->tv_sec) {
        return (1);
    } else if (a->tv_sec < b->tv_sec) {
        return (-1);
    }

    /* secs are equal; check usec */
    if (a->tv_usec > b->tv_usec)
        return (1);
    else if (a->tv_usec < b->tv_usec)
        return (-1);
    else
        return (0);
}

/* XXX: is int the proper return value? */
int
rho_timeval_to_ms(const struct timeval *tv)
{
    int ms = 0;

    ms = tv->tv_sec * 1000;
    ms += (tv->tv_usec / 1000);

    return (ms);
}

double
rho_timeval_to_sec_double(const struct timeval *tv)
{
    return (tv->tv_sec + (tv->tv_usec/1.0e6));
}
