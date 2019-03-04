#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "rho_file.h"
#include "rho_log.h"
#include "rho_mem.h"

/* 
 * one-shot function for reading an entire file 
 *
 * fopen sets errno
 * fseek sets errno
 *
 */
int
rho_file_readall(const char *path, uint8_t **buf, size_t *len)
{
    int error = 0;
    FILE *fp = NULL;
    long size = 0;
    size_t nread = 0;

    *buf = NULL;
    *len = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        rho_errno_warn(errno, "fopen(\"%s\", \"rb\") failed", path);
        error = -1;
        goto fail;
    }

    error = fseek(fp, 0L, SEEK_END);
    if (error == -1) {
        rho_errno_warn(errno, "fseek(fp for \"%s\", 0L, SEEK_END) failed", path);
        goto fail;
    }

    size = ftell(fp);
    if (size == - 1) {
        rho_errno_warn(errno, "ftell(fp for \"%s\")", path);
        error = -1;
        goto fail;
    }

    error = fseek(fp, 0L, SEEK_SET);
    if (error == -1) {
        rho_errno_warn(errno, "fseek(fp for \"%s\", 0L, SEEK_END) failed", path);
        goto fail;
    }

    *buf = rhoL_malloc(size);
    
    nread = fread(*buf, 1, size, fp);
    if ((size == 0) || (nread != ((size_t)size))) {
        if (ferror(fp) != 0) {
            rho_warn("ferror reading file \"%s\"", path);
            error = -1;
            goto fail;
        }
    }
    
    *len = nread;
    error = 0;
    goto succeed;

fail:
    if (*buf != NULL) {
        rhoL_free(*buf);
        *buf = NULL;
    }

succeed:
    if (fp != NULL)
        fclose(fp);

    return (error);
}

/* one-shot function for writing an entire file */
int
rho_file_writeall(const char *path, uint8_t *buf, size_t len)
{
    int error = 0;
    FILE *fp = NULL;
    size_t nput = 0;

    fp = fopen(path, "wb");
    if (fp == NULL) {
        rho_errno_warn(errno, "fopen(%s, \"wb\") failed", path);
        goto fail;
    }

    nput = fwrite(buf, 1, len, fp);
    if (nput != len) {
        rho_warn("fwrite(\"%s\") expected to write %zu bytes, only wrote %zu",
                path, len, nput);
        goto fail;
    }
    
    error = 0;
    goto succeed;

fail:
    error = 1;
succeed:
    if (fp != NULL)
        fclose(fp);

    return (error);
}

#if 0
struct rho_fileiter *
rho_fileiter_create(const char *path, const char *sep, bool keepsep)
{

}

struct rho_fileiter *
rho_file_tokeniter_createfromfd(int fd, const char *sep, bool keepsep)
{

}

/* return NULL on end */
char *
rho_fileiter_next_alloc(struct rho_file_lineiter *iter)
{


}

const char *
rho_fileiter_next(struct rho_file_lineiter *iter, size_t *len)
{


}

void
rho_fileiter_destroy(struct rho_file_lineiter *iter)
{

}

struct rho_fileiter *
rho_file_blockiter_create(const char *path, size_t blksize)
{

}

struct rho_file_blockiter *
rho_fileiterblk_createfromfd(int fd, size_t blksize)
{

}


rho_file_blockiter_next(struct rho_file_blockiter *iter, void *buf)
{


}

void
rho_file_blockiter_destroy(struct rho_file_blockiter *iter)
{

}
#endif
