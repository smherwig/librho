#ifndef _RHO_OPENSSL_H_
#define _RHO_OPENSSL_H_

#include "rho_decls.h"


RHO_DECLS_BEGIN

/* error reporting */
void rho_openssl_warn(const char *fmt, ...);
void rho_openssl_die(const char *fmt, ...);

RHO_DECLS_END

#endif /* _RHO_OPENSSL_H_ */
