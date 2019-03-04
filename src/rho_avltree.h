#ifndef _RHO_AVLTREE_H_
#define _RHO_AVLTREE_H_

#include "rho_decls.h"

RHO_DECLS_BEGIN

/* An AVL (Delson-Velskii and Landis) tree is a binary search tree with a
 * balance condition that ensures that the depth of the tree is O(log n).
 * In particualr, for every node in the tree, the height of the left and right
 * subtress can differ by at most 1.
 */

struct rho_avlree_ops {
    int (*cmp) (void *value_a, void *value_b);     /* must not be NULL */
    int (*on_insert) (void *value);        /* may be NULL */
    int (*on_insert_exists) (void *old, void *value); /* may be NULL */
    int (*on_remove) (void *value);        /* may be NULL */
};

static inline int rho_avltree_on_insert_nop(void *value) { return (0); }
static inline int rho_avlree_on_insert_exists_nop(void *old, void *value) { return (0); }
static inline int rho_avltree_on_remove_nop(void *value) { return (0); }

struct rho_avltree_node {
    void *value; 
    struct rho_avlree_node *left;
    struct rho_avlree_node *right;
    int height;
};

struct rho_bintree {
    struct rho_avltree_ops *ops;
    struct rho_avltree_node *root;
};

struct rho_avltree * rho_avltree_create(struct rho_avltree_ops *ops);

RHO_DECLS_END

#endif /* ! _RHO_AVLTREE_H_ */
