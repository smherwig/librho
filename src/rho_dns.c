#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>

#include "rho_dns.h"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_sock.h"

void
rho_dns_lookup_result_array_free(struct rho_dns_lookup_result *array)
{
    rhoL_free(array);
}

int
rho_dns_lookup(const char *host, int flags,
        struct rho_dns_lookup_result **results, size_t *count)
{
    int error = 0;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *iter = NULL;
    struct rho_dns_lookup_result *resarray = NULL;
    int n = 0;
    int i = 0;

    /* XXX: I don't know if I shoudl set ai_socktype and ai_protocol; my
     * thought is to reduce the likelihood of duplicate results from
     * getaddrinfo
     */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    /* TODO: set AI_CANONNAME? */

    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
    /* usuable addresses */
    if (flags & RHO_DNS_LOOKUP_UNUSABLE) {
#if defined(RHO_PLAT_MACOS)
        /* 
         * XXX: this actually depends on the version of macos; on El Captian
         * (10.11.6), this flag is not present.  I'm just going to comment out
         * for now; hte flags argument to rho_dns_lookup needs some work anway
         * -- I would probably model after node.js' dns routines, as their
         *  options and naming are straight-forward.
         */
        ;
        //hints.ai_flags = AI_UNUSABLE;
#endif
    }

    /* family */
    hints.ai_family = PF_UNSPEC;

    if (flags & RHO_DNS_LOOKUP_IPv4)
        hints.ai_family = PF_INET;

    if (flags & RHO_DNS_LOOKUP_IPv6)
        hints.ai_family = PF_INET6;

    if ((flags & RHO_DNS_LOOKUP_IPv6) && (flags & RHO_DNS_LOOKUP_IPv4))
        hints.ai_family = PF_UNSPEC;

    error = getaddrinfo(host, NULL, &hints, &res);
    if (error != 0) {
        rho_warn("getaddrinfo(\"%s\") failed: %s", host, gai_strerror(error));
        goto done;
    }

    /* get the number of entries */
    for (iter = res; iter != NULL; iter = iter->ai_next)
        n++;

    /* contruct rho_dns_lookup_result array */
    resarray = rhoL_mallocarray(n, sizeof(struct rho_dns_lookup_result), RHO_MEM_ZERO);
    for (i = 0, iter = res; iter != NULL; i++, iter = iter->ai_next) {
        resarray[i].family = iter->ai_family;

        switch (iter->ai_family) {
        case PF_INET:
            rhoL_inet_ntop(iter->ai_family, 
                    &(((struct sockaddr_in *)iter->ai_addr)->sin_addr), 
                    resarray[i].ipstr, INET6_ADDRSTRLEN);
            break;
        case PF_INET6:
            rhoL_inet_ntop(iter->ai_family, 
                    &(((struct sockaddr_in6 *)iter->ai_addr)->sin6_addr), 
                    resarray[i].ipstr, INET6_ADDRSTRLEN);
            break;
        default:
            rho_die("getaddrinfo result: unknown ai_family (%d)", iter->ai_family);
        } 
    }

    freeaddrinfo(res);
    *results = resarray;
    *count = n;

done:
    return (error);
}

/* host should be NI_MAXHOST] (netdb.h) */
/* returns 0 or success; on error, returns a gai error code 
 * Failure includes DNS not being able to resolve the ip to a hostname.
 */
int
rho_dns_reverse_lookup(const char *ipstr, char *host, size_t hostlen)
{
    int error = 0;
    struct addrinfo hints;
    struct addrinfo *resolved = NULL;

    /* convert ipstr to sockaddr */
    memset(&hints, 0x00, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    error = getaddrinfo(ipstr, NULL, &hints, &resolved);
    if (error != 0)
        rho_die("getaddrinfo(\"%s\") failed: %s", ipstr, gai_strerror(error));

    /* resolved sockaddr to hostname */
    error = getnameinfo(resolved->ai_addr, (socklen_t)resolved->ai_addrlen,
            host, (socklen_t)hostlen, NULL, 0, NI_NAMEREQD);
    if (error != 0) {
        rho_warn("getnameinfo(\"%s\") failed: %s", ipstr, gai_strerror(error));
        goto done;
    }
    
    freeaddrinfo(resolved);

done:
    return (error);
}

#if 0

/* arbitrary query */
rho_dns_query(int class, int type, )
{
    res_send();
}

rho_dns_query_async()
{

}

rho_dns_getdomainname(void)
{
    getdomainname()
}

rho_dns_gethostname(void)
{
    gethostname()
}

rho_dns_gethostips(void)
{
    getifaddrs()
    freeifaddrs()
}

#endif
