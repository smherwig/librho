#ifndef _RHO_LOG_H_
#define _RHO_LOG_H_

#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

/*
 * ASSERTIONS
 */

#define RHO_ASSERT(cond) assert(cond)

/* 
 * if you want to long thread id, 
 * add "tid=%lu", (unsigned long)pthread_self()
 */

/*
 * TRACING FUNCTION ENTRACE AND EXIT
 */

#ifdef RHO_TRACE
#define RHO_TRACE_ENTER(fmt, ...) \
    fprintf(stderr, "> %s: " fmt "\n", __func__, ##__VA_ARGS__)

#define RHO_TRACE_EXIT(fmt, ...) \
    fprintf(stderr, "< %s: "fmt "\n", __func__, ##__VA_ARGS__)
#else
#define RHO_TRACE_ENTER(fmt, ...)
#define RHO_TRACE_EXIT(fmt, ...)
#endif

/*
 * SIMPLE LOGGING TO STDERR, WITH/WITHOUT ABORTS
 */

#ifdef RHO_DEBUG
#define rho_debug(fmt, ...) \
    fprintf(stderr, "[debug] %s:%d " fmt "\n", \
            __func__, __LINE__,##__VA_ARGS__)
#else
#define rho_debug(fmt, ...) (void)(0)
#endif

#define rho_errno_die(errnum, fmt, ...) \
    do { \
        char buf__[1024] = { 0 }; \
        (void)strerror_r(errnum, buf__, sizeof(buf__)); \
        fprintf(stderr, "[die] %s:%d " fmt ": %s\n", \
                __func__, __LINE__,##__VA_ARGS__, buf__); \
        exit(1); \
    } while (0)

#define rho_die(fmt, ...) \
    do { \
        fprintf(stderr, "[die] %s:%d " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__); \
        exit(1); \
    } while (0)

#define rho_errno_warn(errnum, fmt, ...) \
    do { \
        char buf__[1024] = { 0 }; \
        (void)strerror_r(errnum, buf__, sizeof(buf__)); \
        fprintf(stderr, "[warn] %s:%d " fmt ": %s\n", \
                __func__, __LINE__,##__VA_ARGS__, buf__); \
    } while (0)

#define rho_warn(fmt, ...) \
        fprintf(stderr, "[warn] %s:%d " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__)

void rho_hexdump(const void *p, size_t len, const char *fmt, ...);

/*
 * APPLICATION-LEVEL LOGGER
 */

enum rho_log_level {
    RHO_LOG_EMERG = 1,
    RHO_LOG_ALERT,
    RHO_LOG_CRIT,
    RHO_LOG_ERR,
    RHO_LOG_WARN,
    ROH_LOG_NOTICE,
    RHO_LOG_INFO,
    RHO_LOG_DEBUG
};

#define RHO_LOG_MAX_LINE_LENGTH     512

struct rho_log;

typedef void (*rho_log_writer_fn) (struct rho_log *, enum rho_log_level level,
        const char *buf, size_t len);

struct rho_log {
    int                 fd;
    enum rho_log_level  level;
    rho_log_writer_fn   writer; 
    void *              wdata;
};

void rho_log_default_writer(struct rho_log *log, enum rho_log_level level,
        const char *buf, size_t len);

struct rho_log * rho_log_create(int fd, enum rho_log_level level,
        rho_log_writer_fn writer, void *wdata);

void rho_log_destroy(struct rho_log *log);

void rho_log(struct rho_log *log, enum rho_log_level level,
        const char *fmt, ...);

#define rho_log_emerg(log, fmt, ...) \
    rho_log(log, RHO_LOG_EMERG, fmt,##__VA_ARGS__)

#define rho_log_alert(log, fmt, ...) \
    rho_log(log, RHO_LOG_ALERT, fmt,##__VA_ARGS__)

#define rho_log_crit(log, fmt, ...) \
    rho_log(log, RHO_LOG_CRIT, fmt,##__VA_ARGS__)

#define rho_log_err(log, fmt, ...) \
    rho_log(log, RHO_LOG_ERR, fmt,##__VA_ARGS__)

#define rho_log_warn(log, fmt, ...) \
    rho_log(log, RHO_LOG_WARN, fmt,##__VA_ARGS__)

#define rho_log_notice(log, fmt, ...) \
    rho_log(log, RHO_LOG_NOTICE, fmt,##__VA_ARGS__)

#define rho_log_info(log, fmt, ...) \
    rho_log(log, RHO_LOG_INFO, fmt,##__VA_ARGS__)

#define rho_log_debug(log, fmt, ...) \
    rho_log(log, RHO_LOG_DEBUG, fmt,##__VA_ARGS__)

void rho_log_errno(struct rho_log *log, enum rho_log_level level,
        int errnoval, const char *fmt, ...);

#define rho_log_errno_emerg(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_EMERG, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_alert(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_ALERT, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_crit(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_CRIT, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_err(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_ERR, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_warn(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_WARN, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_notice(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_NOTICE, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_info(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_INFO, errnoval, fmt,##__VA_ARGS__)

#define rho_log_errno_debug(log, errnoval, fmt, ...) \
    rho_log_errno(log, RHO_LOG_DEBUG, errnoval, fmt,##__VA_ARGS__)

void rho_log_redirect_stderr(struct rho_log *log);

void rho_log_set_level(struct rho_log *log, enum rho_log_level level);

RHO_DECLS_END

#endif /* ! _ RHO_LOG_H_ */

