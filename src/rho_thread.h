#ifndef _RHO_THREAD_H_
#define _RHO_THREAD_H_

#include <pthread.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

void rhoL_pthread_mutex_init(pthread_mutex_t *  mutex,
        const pthread_mutexattr_t *  attr);
void rhoL_pthread_mutex_destroy(pthread_mutex_t *mutex);
void rhoL_pthread_mutex_lock(pthread_mutex_t *mutex);
void rhoL_pthread_mutex_unlock(pthread_mutex_t *mutex);

void rhoL_pthread_cond_init(pthread_cond_t *  cond,
        const pthread_condattr_t *  attr);
void rhoL_pthread_cond_destroy(pthread_cond_t *cond);
void rhoL_pthread_cond_signal(pthread_cond_t *cond);
void rhoL_pthread_cond_wait(pthread_cond_t *  cond,
        pthread_mutex_t *  mutex);

/* returns 0 on success, 1 on timeout */
int rhoL_pthread_cond_timedwait(pthread_cond_t *cond,
        pthread_mutex_t *mutex, const struct timespec *abstime);

void rhoL_pthread_create(pthread_t * thread,
        const pthread_attr_t * attr,
        void * (*start_routine)(void *),
        void * arg);

RHO_DECLS_END

#endif /* !_RHO_THREAD_H_ */
