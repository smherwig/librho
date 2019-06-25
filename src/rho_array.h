#ifndef _RHO_ARRAY_H_
#define _RHO_ARRAY_H_

#include <sys/types.h>

#include "rho_decls.h"

#include "rho_log.h"
#include "rho_mem.h"

RHO_DECLS_BEGIN

#define RHO_ARRAY_EXTENT    8

#define RHO_ARRAY_DECLARE(name, elem_type) \
    struct name { \
        size_t size; \
        size_t cap; \
        size_t elem_size; \
        elem_type * elems; \
    }

#define RHO_ARRAY_INIT(elem_type)  { 0, 0, sizeof(elem_type), NULL }

#define RHO_ARRAY_ALLOC_INIT(a, elem_type)  \
    do { \
        (a) = rhoL_zalloc(sizeof(*a)); \
        (a)->elem_size = sizeof(elem_type); \
    } while (0) 

#define RHO_ARRAY_CLEAR(a) \
    do { \
        if (RHO_ARRAY_C_ARRAY((a)) != NULL) { \
            rhoL_free(RHO_ARRAY_C_ARRAY((a))); \
            RHO_ARRAY_C_ARRAY((a)) = NULL; \
        } \
        RHO_ARRAY_SIZE((a)) = 0; \
        (a)->cap = 0; \
    } while (0);

#define RHO_ARRAY_CLEAREXT(a, elem_dtor) \
    do { \
        size_t i; \
        for (i = 0; i < (a)->size; i++) \
            (elem_dtor)((a)->elems[i]); \
        if ((a)->elems != NULL) { \
            rhoL_free((a)->elems); \
            (a)->elems = NULL; \
        } \
        (a)->size = 0; \
        (a)->cap = 0; \
    } while (0);

#define RHO_ARRAY_SIZE(a) \
    ( (a)->size )

#define RHO_ARRAY_C_ARRAY(a) \
    ( (a)->elems )

#define RHO_ARRAY_GET(val, a, i) \
    do { \
        size_t asize = (a)->size; \
        if (i >= asize) \
            rho_die("RHO_ARRAY_GET: index (%zu) >= array size (%zu)\n", (size_t)i, asize); \
        (val) = (a)->elems[i]; \
    } while (0)

/* 
 * the pragma is because, in the case of i=0, GCC will complain about 0 > asize,
 * namely: "comparison of unsigned expression < 0 is always false".  I
 * guard against this condition by the i != 0 check in the if statement, but GCC isn't
 * smart enough to take this into account.
 */
#define RHO_ARRAY_INSERT(a, i, val) \
    do { \
        size_t j = 0; \
        size_t asize = (a)->size; \
_Pragma("GCC diagnostic push") \
_Pragma("GCC diagnostic ignored \"-Wtype-limits\"") \
        if (((i) != 0) && ((i) > asize)) \
            rho_die("RHO_ARRAY_INSERT: index (%zu) > array size (%zu)\n", (size_t)i, asize); \
_Pragma("GCC diagnostic pop") \
        if (asize == (a)->cap) { \
            (a)->cap += RHO_ARRAY_EXTENT; \
            (a)->elems = rhoL_reallocarray((a)->elems, (a)->cap, (a)->elem_size, 0); \
        } \
        for (j = asize; j > (i); j--) \
            (a)->elems[j] = (a)->elems[j-1]; \
        (a)->elems[i] = (val); \
        (a)->size++; \
    } while (0)

#define RHO_ARRAY_REMOVE(val, a, i) \
    do { \
        size_t j = 0; \
        size_t asize = (a)->size; \
        if (i >= asize) \
            rho_die("RHO_ARRAY_REMOVE: index (%zu) >= array size (%zu)\n", (size_t)i, asize); \
        (val) = (a)->elems[i]; \
        for (j = i; j < asize - 1; j++) \
            (a)->elems[j] = (a)->elems[j+1]; \
        (a)->size--; \
    } while (0)

RHO_DECLS_END

#endif /* !_RHO_ARRAY_H_ */
