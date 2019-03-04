#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "rho_buf.h"
#include "rho_tftp.h"

void
rho_tftp_rrq_packet(struct rho_buf *buf, const char *path, const char *mode)
{
    off_t start = 0;

    start = rho_buf_tell(buf);

    rho_buf_writeu16be(buf, RHO_TFTP_OP_RRQ);
    rho_buf_puts_nul(buf, path);
    rho_buf_puts_nul(buf, mode);

    rho_buf_seek(buf, start, SEEK_SET);
}

void
rho_tftp_wrq_packet(struct rho_buf *buf, const char *path, const char *mode)
{
    off_t start = 0;

    start = rho_buf_tell(buf);

    rho_buf_writeu16be(buf, RHO_TFTP_OP_WRQ);
    rho_buf_puts_nul(buf, path);
    rho_buf_puts_nul(buf, mode);

    rho_buf_seek(buf, start, SEEK_SET);
}

void
rho_tftp_data_packet(struct rho_buf *buf, uint16_t blknum, void *data,
        size_t datalen)
{
    off_t start = 0;

    start = rho_buf_tell(buf);

    rho_buf_writeu16be(buf, RHO_TFTP_OP_DATA);
    rho_buf_writeu16be(buf, blknum);
    rho_buf_write(buf, data, datalen);

    rho_buf_seek(buf, start, SEEK_SET);
}

void
rho_tftp_ack_packet(struct rho_buf *buf, uint16_t blknum)
{
    off_t start = 0;

    start = rho_buf_tell(buf);

    rho_buf_writeu16be(buf, RHO_TFTP_OP_ACK);
    rho_buf_writeu16be(buf, blknum);

    rho_buf_seek(buf, start, SEEK_SET);
}

void
rho_tftp_error_packet(struct rho_buf *buf, uint16_t errcode, const char *errmsg)
{
    off_t start = 0;

    start = rho_buf_tell(buf);

    rho_buf_writeu16be(buf, RHO_TFTP_OP_ERROR);
    rho_buf_writeu16be(buf, errcode);
    rho_buf_puts_nul(buf, errmsg);

    rho_buf_seek(buf, start, SEEK_SET);
}

#if 0
int
rho_tftp_peek_op(rho_buf *buf, uint16_t *op)
{
    return (rho_buf_preadu16be(buf, op));
}

/* what do you want the position of the buf to be at the end of this
 * function?
 */
int
rho_tftp_parse_rwreq(struct rho_buf *buf, char *path, char *mode)
{
    int error = 0;
    uint16_t op = 0;
    off_t tmpoff = 0;
    off_t pathoff = 0;
    off_t modeoff = 0;
    size_t buflen = 0;

    buflen = rho_buf_length(buf);

    error = rho_buf_readu16be(buf, &op);
    if (error == -1)
        goto fail;

    if (op != RHO_TFTP_RRQ && op != RHO_TFTP_WRQ)
        goto fail;

    /* find path's terminating null */
    tmpoff = rho_buf_index_byte(path, 0x00);
    if (tmpoff == - 1)
        goto fail;

    path = rho_buf_raw(buf, 0, SEEK_CUR);  

    if (tmpoff >= buflen)
        goto fail;

    rho_buf_seek(buf, tmpoff + 1, SEEK_SET);

    /* find mode's terminating null */
    tmpoff = rho_buf_index_byte(path, 0x00);
    if (tmpoff == - 1)
        goto fail;

    if (tmpoff != buflen)
        goto fail;

    mode = rho_buf_raw(buf, 0, SEEK_CUR);
    
    goto success;

fail:
    errno = EBADMSG;
success:
    return (error);
}

int
rho_tftp_parse_data(struct rho_buf *buf, uint16_t *blknum, void *data)
{
    int error = 0;
    uint16_t op = 0;
    size_t buflen = 0;

    buflen = rho_buf_length(buf);

    error = rho_buf_readu16be(buf, &op);
    if (error == -1)
        goto fail;

    if (op != RHO_TFTP_DATA)
        goto fail;
}

int
rho_tftp_parse_error(struct rho_buf *buf, uint16_t *errcode, char *errmsg)
{
    int error = 0;
    uint16_t op = 0;
    size_t buflen = 0;

    buflen = rho_buf_length(buf);

    error = rho_buf_readu16be(buf, &op);
    if (error == -1)
        goto fail;

    if (op != RHO_TFTP_ERROR)
        goto fail;

}
#endif
