#ifndef _RHO_DNS_H_
#define _RHO_DNS_H_

#include <netinet/in.h>

#include <stddef.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

#define RHO_DNS_LOOKUP_UNUSABLE (1<<0)
#define RHO_DNS_LOOKUP_IPv4     (1<<1)
#define RHO_DNS_LOOKUP_IPv6     (1<<2)

struct rho_dns_lookup_result {
    int family;
    char ipstr[INET6_ADDRSTRLEN];
};

void rho_dns_lookup_result_array_free(struct rho_dns_lookup_result *array);

int rho_dns_lookup(const char *host, int flags,
        struct rho_dns_lookup_result **results, size_t *count);

int rho_dns_reverse_lookup(const char *ipstr, char *host, size_t hostlen);

RHO_DECLS_END

#endif /* _RHO_DNS_H_ */
