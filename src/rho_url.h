#ifndef _RHO_URL_H_
#define _RHO_URL_H_

#include <stdbool.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

struct rho_url {
    char *scheme;
    char *authority;
    char *userinfo;
    char *user;
    char *password;
    char *host;
    char *port;
    char *path;
    char *params;
    char *query;
    char *fragment;
};

struct rho_url * rho_url_parse(const char *s);
void rho_url_destroy(struct rho_url *url);

char * rho_url_tostring(const struct rho_url *url);

#if 0
char * rho_url_encode(const char *s, bool space2plus);
char * rho_url_decode(const char *s, bool plus2space);
#endif

RHO_DECLS_END

#endif /* ! _RHO_URL_H_ */
