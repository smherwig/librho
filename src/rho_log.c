#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "rho_fd.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_str.h"

static size_t rho_log_line_add_newline(char *line, size_t len);

void
rho_hexdump(const void *p, size_t len, const char *fmt, ...)
{
    va_list ap;
    size_t i = 0;
    const uint8_t *pc = p;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "(%lu bytes):", len);
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0)
            fprintf(stderr, "\n0x%04lx:  ", i);
        fprintf(stderr, "%02x ", pc[i]);
    }
    fprintf(stderr, "\n");
}

static const char * rho_log_level_strs[] = {
    "",
    "emerg",
    "alert",
    "crit",
    "err",
    "warn",
    "notice",
    "info",
    "debug"
};

void
rho_log_default_writer(struct rho_log *log, enum rho_log_level level,
        const char *buf, size_t len)
{
    char prefix[56] = { 0 };
    size_t n = 0;
    time_t t;
    struct tm tm;

    (void)time(&t);
    (void)gmtime_r(&t, &tm);
    // 1234/67/89 1112:1314:1516 181920 
    // so the timestamp needs 20 chars
    n = strftime(prefix, sizeof(prefix), "%Y/%m/%d %H:%M:%S UTC", &tm);
    if (n == 0)
        rho_die("strftime returned 0");

    // the [level] needs 8 chars
    // TODO: not sure what max pid needs; let's say 15 chars
    // dash is 1 char
    // there are 4 space chars
    sprintf(prefix + n, " [%s] %lu - ", rho_log_level_strs[level],
            (unsigned long)getpid());

    /* TODO: make one call; not two */
    (void)rho_fd_writen(log->fd, prefix, strlen(prefix));
    (void)rho_fd_writen(log->fd, buf, len);
}

struct rho_log *
rho_log_create(int fd, enum rho_log_level level,
        rho_log_writer_fn writer, void *wdata)
{
    struct rho_log *log = NULL;

    log = rhoL_zalloc(sizeof(*log));
    log->fd = fd;
    log->level = level;
    log->writer = writer;
    log->wdata = wdata;

    return (log);
}

void
rho_log_destroy(struct rho_log *log)
{
    rhoL_free(log);
}

/*
 * returns new line length
 */
static size_t
rho_log_line_add_newline(char *line, size_t len)
{
    size_t n = len;

    if (n == (RHO_LOG_MAX_LINE_LENGTH - 1)) {
        /* overwrite last char with a newline */
        line[len-1] = '\n';
    } else if ((n == 0) || (line[n-1] != '\n')) {
        /* 
         * append a newline if the line is zero-length or
         * if the last char isn't already  a newline 
         */
        line[n] = '\n';
        n++;
    }

    return (n);
}

void
rho_log(struct rho_log *log, enum rho_log_level level, const char *fmt, ...)
{
    char line[RHO_LOG_MAX_LINE_LENGTH] = { 0 };
    va_list ap;
    int i = 0;
    size_t n = 0;

    if ((level > log->level) || (log->writer == NULL))
        return;

    va_start(ap, fmt);
    i = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (i < 0)
        rho_die("vsnprintf(\"%s\") returned %d", fmt, i);

    n = strlen(line);
    RHO_ASSERT(n < RHO_LOG_MAX_LINE_LENGTH);
    n = rho_log_line_add_newline(line, n);

    log->writer(log, level, line, n);
}

void
rho_log_errno(struct rho_log *log, enum rho_log_level level, int errnoval,
        const char *fmt, ...)
{
    char line[RHO_LOG_MAX_LINE_LENGTH] = { 0 };
    va_list ap;
    int i = 0;
    size_t n = 0;

    if ((level > log->level) || (log->writer == NULL))
        return;

    i = snprintf(line, sizeof(line), "[errno=%d] ", errnoval);
    if (i < 0)
        rho_die("snprintf returned %d", i);

    (void)strerror_r(errnoval, line + i, sizeof(line) - i);
    n = strlen(line);
    line[n] = ':'; n++;
    line[n] = ' '; n++;

    va_start(ap, fmt);
    i = vsnprintf(line + n, sizeof(line) - n, fmt, ap);
    va_end(ap);
    if (i < 0)
        rho_die("vsnprintf(\"%s\") returned %d", fmt, i);

    /* if last char not a newline, make it a newline */
    n = strlen(line);
    RHO_ASSERT(n < RHO_LOG_MAX_LINE_LENGTH);
    n = rho_log_line_add_newline(line, n);

    log->writer(log, level, line, n);
}

void
rho_log_redirect_stderr(struct rho_log *log)
{
    if (log->fd == STDERR_FILENO)
        return;

   if (dup2(log->fd, STDERR_FILENO) != STDERR_FILENO)
       rho_errno_warn(errno, "dup2(%d, %d) failed", log->fd, STDERR_FILENO);
}

void
rho_log_set_level(struct rho_log *log, enum rho_log_level level)
{
    log->level = level;
}
