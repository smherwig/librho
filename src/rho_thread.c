#include <pthread.h>

#include "rho_log.h"
#include "rho_thread.h"

void
rhoL_pthread_mutex_init(pthread_mutex_t *  mutex,
        const pthread_mutexattr_t *  attr)
{
    int error = 0;

    error = pthread_mutex_init(mutex, attr);
    if (error != 0)
        rho_errno_die(error, "pthread_mutex_init");
}

void
rhoL_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    int error = 0;

    error = pthread_mutex_destroy(mutex);
    if (error != 0)
        rho_errno_die(error, "pthread_mutex_destroy");
}

void
rhoL_pthread_mutex_lock(pthread_mutex_t *mutex)
{
    int error = 0;

    error = pthread_mutex_lock(mutex);
    if (error != 0)
        rho_errno_die(error, "pthread_mutex_lock");
}

void
rhoL_pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    int error = 0;

    error = pthread_mutex_unlock(mutex);
    if (error != 0)
        rho_errno_die(error, "pthread_mutex_unlock");
}

/*
 * condition variable
 */

void
rhoL_pthread_cond_init(pthread_cond_t *  cond,
        const pthread_condattr_t *  attr)
{
    int error = 0;

    error = pthread_cond_init(cond, attr);
    if (error != 0)
        rho_errno_die(error, "pthread_cond_init");
}

void
rhoL_pthread_cond_destroy(pthread_cond_t *cond)
{
    int error = 0;

    error = pthread_cond_destroy(cond);
    if (error != 0)
        rho_errno_die(error, "pthread_cond_destroy");
}

void
rhoL_pthread_cond_signal(pthread_cond_t *cond)
{
    int error = 0;

    error = pthread_cond_signal(cond);
    if (error != 0)
        rho_errno_die(error, "pthread_cond_signal");
}

void
rhoL_pthread_cond_wait(pthread_cond_t *  cond,
        pthread_mutex_t *  mutex)
{
    int error = 0;

    error = pthread_cond_wait(cond, mutex);
    if (error != 0)
        rho_errno_die(error, "pthread_cond_wait");
}

int
rhoL_pthread_cond_timedwait(pthread_cond_t *cond,
        pthread_mutex_t *mutex, const struct timespec *abstime)
{
    int error = 0;

    error = pthread_cond_timedwait(cond, mutex, abstime);
    if (error != 0) {
        if (error == ETIMEDOUT)
            return (1);
        else
           rho_errno_die(error, "pthread_cond_timedwait"); 
    }

    return (0);
}

/*
 * thread
 */

void
rhoL_pthread_create(pthread_t * thread,
        const pthread_attr_t * attr,
        void * (*start_routine)(void *),
        void * arg)
{
    int error = 0;

    error = pthread_create(thread, attr, start_routine, arg);
    if (error != 0)
        rho_errno_die(error, "pthread_create");
}

