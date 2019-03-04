#ifndef _RHO_FILE_H_
#define _RHO_FILE_H_

#include "rho_decls.h"

#include <stddef.h>
#include <stdint.h>

RHO_DECLS_BEGIN

/* return 0 on success; -1 on failure */
int rho_file_readall(const char *path, uint8_t **buf, size_t *len);
int rho_file_writeall(const char *path, uint8_t *buf, size_t len);

RHO_DECLS_END

#endif /* _RHO_FILE_H_ */
