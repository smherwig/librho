#ifndef _RHO_TFTP_H_
#define _RHO_TFTP_H_

#include <stddef.h>
#include <stdint.h>

#include "rho_decls.h"

#include "rho_buf.h"

RHO_DECLS_BEGIN

#define RHO_TFTP_DEFAULT_PORT       69
#define RHO_TFTP_MAX_DATA_LENGTH    512
    
#define RHO_TFTP_OP_RRQ     1
#define RHO_TFTP_OP_WRQ     2
#define RHO_TFTP_OP_DATA    3
#define RHO_TFTP_OP_ACK     4
#define RHO_TFTP_OP_ERROR   5

#define RHO_TFTP_MODE_NETASCII  "netascii"
#define RHO_TFTP_MODE_OCTET     "octet"

void rho_tftp_rrq_packet(struct rho_buf *buf, const char *path,
        const char *mode);

void rho_tftp_wrq_packet(struct rho_buf *buf, const char *path,
        const char *mode);

void rho_tftp_data_packet(struct rho_buf *buf, uint16_t blknum, void *data,
        size_t datalen);

void rho_tftp_ack_packet(struct rho_buf *buf, uint16_t blknum);

void rho_tftp_error_packet(struct rho_buf *buf, uint16_t error,
        const char *errmsg);

RHO_DECLS_END

#endif /* _RHO_TFTP_H_ */
