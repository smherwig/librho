#include <sys/time.h>   /* gettimeofday */

#include <stdbool.h>
#include <poll.h>

#include "rho_event.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_queue.h"
#include "rho_time.h"

#define rho_event_has_timeout(tv) \
    (((event)->timeout.tv_sec != 0) || ((event)->timeout.tv_usec != 0))

static bool
rho_event_has_expired(const struct rho_event *event, struct timeval *now)
{
    return (rho_event_has_timeout(event) && 
            (rho_timeval_cmp(&event->expires, now) < 0));
}

static void
rho_event_loop_update_min_timeout(struct rho_event_loop *loop)
{
    struct rho_event * event = NULL;

    RHO_TAILQ_FOREACH(event, &loop->pending, event_next) {
        if (rho_event_has_timeout(event) && 
                (rho_timeval_cmp(&event->timeout, &loop->min_timeout) < 0)) {
            loop->min_timeout = event->timeout;
        }
    }
}

static void
rho_event_loop_dispatch_one(struct rho_event_loop *loop,
        struct rho_event *event, int what)
{
    RHO_TRACE_ENTER("event->fd=%d, what=%d", event->fd, what);

    if (event->flags & RHO_EVENT_PERSIST) {
        if (rho_event_has_timeout(event)) {
            rho_timeval_add(&event->timeout, &loop->cur_time, 
                    &event->expires);
        }
    } else {
        rho_event_loop_remove(loop, event);
    }

    event->cb(event, what, loop);

    if (event->state == RHO_EVENT_NONPENDING)
        rho_event_destroy(event);

    RHO_TRACE_EXIT();
}

static void
rho_event_loop_dispatch_timeouts(struct rho_event_loop *loop)
{
    struct rho_event *event = NULL;
    struct rho_event *tmp = NULL;

    RHO_TRACE_ENTER();

    RHO_TAILQ_FOREACH_SAFE(event, &loop->pending, event_next, tmp) {
        if (rho_event_has_expired(event, &loop->cur_time))
            rho_event_loop_dispatch_one(loop, event, RHO_EVENT_TIMEOUT);
    }

    RHO_TRACE_EXIT();
}

static void
rho_event_loop_construct_pollfds(struct rho_event_loop *loop)
{
    struct rho_event *event = NULL;
    nfds_t i = 0;

    RHO_ASSERT(loop != NULL);

    RHO_TRACE_ENTER();

    if (loop->num_pending > loop->nfds_cap) {
        loop->pollfds = rhoL_reallocarray(loop->pollfds, loop->num_pending,
                sizeof(struct pollfd), 0);
        loop->nfds_cap = loop->num_pending;
    }

    RHO_TAILQ_FOREACH(event, &loop->pending, event_next) {
        loop->pollfds[i].fd = event->fd;
        loop->pollfds[i].events = ((event->flags & RHO_EVENT_READ ? POLLIN : 0) |
                    (event->flags & RHO_EVENT_WRITE ? POLLOUT : 0));
        i++;
    }
    RHO_ASSERT(loop->num_pending == (size_t)i);

    loop->nfds = (nfds_t)loop->num_pending;

    RHO_TRACE_EXIT("nfds=%lu", (unsigned long)(loop->nfds));
    return;
}

static void
rho_event_loop_update_time(struct rho_event_loop *loop)
{
    RHO_ASSERT(loop != NULL);

    rhoL_gettimeofday(&loop->cur_time, NULL);
}

struct rho_event *
rho_event_create(int fd, int flags, rho_event_callback cb, void *userdata)
{
    struct rho_event *event = NULL;

    RHO_TRACE_ENTER("fd=%d, flags=%08x", fd, flags);

    event = rhoL_zalloc(sizeof(*event));
    event->fd = fd;
    event->flags = flags;
    event->cb = cb;
    event->userdata = userdata;
    event->state = RHO_EVENT_NONPENDING;

    RHO_TRACE_EXIT();
    return (event);
}

void
rho_event_destroy(struct rho_event *event)
{
    RHO_ASSERT(event != NULL);

    RHO_TRACE_ENTER("event->fd=%d", event->fd);

    rhoL_free(event);

    RHO_TRACE_EXIT();
}

struct rho_event_loop *
rho_event_loop_create(void)
{
    struct rho_event_loop *loop = NULL;

    RHO_TRACE_ENTER();

    loop = rhoL_zalloc(sizeof(*loop));
    loop->stop = false;
    loop->min_timeout.tv_sec = 5; 
    loop->min_timeout.tv_usec = 0;
    RHO_TAILQ_INIT(&loop->pending);

    RHO_TRACE_EXIT();
    return (loop);
}

void
rho_event_loop_destroy(struct rho_event_loop *loop)
{
    RHO_TRACE_ENTER();

    /* TODO: destroy queue */
    rhoL_free(loop);
    if (loop->pollfds != NULL)
        rhoL_free(loop->pollfds);

    RHO_TRACE_EXIT();
}

void
rho_event_loop_add(struct rho_event_loop *loop, struct rho_event *event,
        const struct timeval *tv)
{
    struct timeval now = { .tv_sec = 0, .tv_usec = 0 };

    RHO_ASSERT(loop != NULL);
    RHO_ASSERT(event != NULL);

    RHO_TRACE_ENTER("event->fd=%d", event->fd);

    if (tv != NULL) {
        event->timeout = *tv;
        rhoL_gettimeofday(&now, NULL);
        rho_timeval_add(&event->timeout, &now, &event->expires);

        if (rho_timeval_cmp(tv, &loop->min_timeout) == -1) {
            loop->min_timeout = *tv;
        }
    }

    event->state = RHO_EVENT_PENDING;
    loop->num_pending++;
    RHO_TAILQ_INSERT_TAIL(&loop->pending, event, event_next);

    RHO_TRACE_EXIT("");
}

void
rho_event_loop_remove(struct rho_event_loop *loop, struct rho_event *event)
{
    RHO_ASSERT(loop != NULL);
    RHO_ASSERT(event != NULL);

    RHO_TRACE_ENTER("event->fd=%d", event->fd);

    event->state = RHO_EVENT_NONPENDING;

    RHO_TAILQ_REMOVE(&loop->pending, event, event_next);

    if (rho_event_has_timeout(event) && 
            (!rho_timeval_cmp(&event->timeout, &loop->min_timeout))) {
        rho_event_loop_update_min_timeout(loop);
    }

    loop->num_pending--;

    RHO_TRACE_EXIT("");
}

void
rho_event_loop_dispatch(struct rho_event_loop *loop)
{
    int error = 0;   
    struct pollfd *pollfds = NULL;
    nfds_t nfds = 0;
    struct rho_event *event = NULL;
    struct rho_event *tmp = NULL;
    nfds_t i = 0;
    int what = 0;

    RHO_ASSERT(loop != NULL);

    while (!loop->stop) {

        rho_event_loop_construct_pollfds(loop);
        nfds = loop->nfds;
        pollfds = loop->pollfds;

        error = poll(pollfds, nfds, rho_timeval_to_ms(&loop->min_timeout));
        rho_event_loop_update_time(loop);
        if (((error == -1) && (errno == EINTR)) || (error == 0)) {
            rho_event_loop_dispatch_timeouts(loop);
        } else if (error == -1) {
            rho_errno_die(errno, "poll failed");
        } else {
            i = 0;
            /* 
             * FIXME:
             *  This iteration is incorrect.  The issue is that the pollfds
             *  and loop->pending queue are in-sync at the start of the 
             *  RHO_TAILQ_FOREACH_SAFE loop, but calls to
             *  rho_event_loop_dispatch_one could result in events being added
             *  or removed, which thus make pollfs and loop->pending lists out
             *  of sync.
             *
             *  Now, there are safe ways that the two lists can become out of
             *  sync.  For instance, if the dispatch_one() removes the
             *  current event;
             *
             *  dispathc_one():
             *      removes prior event
             *          probably safe
             *
             *      removes current event (e.g., event i)
             *          safe
             *
             *      removes an upcoming event
             *          could be unsafe
             *
             *      adds an event
             *          unsafe
             */
            RHO_TAILQ_FOREACH_SAFE(event, &loop->pending, event_next, tmp) {
                if (i >= nfds)
                   break; 
                    
                //fprintf(stderr, "i:%lu, pollfds[i].fd:%d, event->fd:%d\n",
                //        (unsigned long)i, pollfds[i].fd, event->fd);
                RHO_ASSERT(pollfds[i].fd == event->fd);

                what = 0;
                if (rho_event_has_expired(event, &loop->cur_time))
                    what = RHO_EVENT_TIMEOUT;
                if (pollfds[i].revents & (POLLOUT | POLLERR | POLLHUP))
                    what |= RHO_EVENT_WRITE;
                if (pollfds[i].revents & (POLLIN | POLLERR | POLLHUP))
                    what |= RHO_EVENT_READ;
                        
                if (what)
                    rho_event_loop_dispatch_one(loop, event, what);

                i++;
            }
        }
    }
}

void
rho_event_loop_stop(struct rho_event_loop *loop)
{
    RHO_ASSERT(loop != NULL);

    RHO_TRACE_ENTER();
    loop->stop = true;
    RHO_TRACE_EXIT();
}
