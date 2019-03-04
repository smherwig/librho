#ifndef _RHO_EVENT_H_
#define _RHO_EVENT_H_

#include <sys/time.h>

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>

#include "rho_decls.h"
#include "rho_queue.h"

RHO_DECLS_BEGIN

/*
 * event flags
 */

/* input/output: an event that becomes active when the provided fd is ready for reading */
#define RHO_EVENT_READ      (1U<<1)
/* input/output: an event that becomes active when the provided fd is ready for writing */
#define RHO_EVENT_WRITE     (1U<<2)
/* output: an event that becomes active after a timeout elapses */
#define RHO_EVENT_TIMEOUT   (1U<<3)
/* input: indicates taht an event is persistent */
#define RHO_EVENT_PERSIST   (1U<<4)

/*
 * event states
 */

#define RHO_EVENT_NONPENDING    (1U<<1)
#define RHO_EVENT_PENDING       (1U<<2)

struct rho_event;
struct rho_event_loop;

typedef void (*rho_event_callback)(struct rho_event *event , int what,
        struct rho_event_loop *loop);

struct rho_event {
    RHO_TAILQ_ENTRY(rho_event) event_next;
    int fd;
    int flags;
    int state;
    rho_event_callback cb;
    void *userdata;
    struct timeval timeout;     /* interval */
    struct timeval expires;      /* wallclock time */
};

RHO_TAILQ_HEAD(rho_event_queue, rho_event); 
struct rho_event_loop {
    struct pollfd *pollfds;
    nfds_t nfds;        /* number of active fds in pollfd array */
    nfds_t nfds_cap;    /* the max number of fds that would fit in array */
    struct rho_event_queue pending;
    size_t num_pending;
    struct timeval min_timeout;     /* interval */
    struct timeval cur_time;        /* wallclock time */
    bool   stop;
};

/* for timers, fd = -1 */
struct rho_event * 
rho_event_create(int fd, int flags, rho_event_callback cb, void *userdata);

void
rho_event_destroy(struct rho_event *event);

struct rho_event_loop *
rho_event_loop_create(void);

void
rho_event_loop_destroy(struct rho_event_loop *loop);

void 
rho_event_loop_add(struct rho_event_loop *loop, struct rho_event *event, 
        const struct timeval *tv);

void 
rho_event_loop_remove(struct rho_event_loop *loop, struct rho_event *event);

void
rho_event_loop_dispatch(struct rho_event_loop *loop);

void
rho_event_loop_stop(struct rho_event_loop *loop);

RHO_DECLS_END

#endif /* ! _RHO_EVENT_H_ */
