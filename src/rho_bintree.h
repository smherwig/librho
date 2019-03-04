#ifndef _RHO_BINTREE_H_
#define _RHO_BINTREE_H_

#include <stdbool.h>

struct rho_bintree_ops {
    int (*cmp) (void *value_a, void *value_b);     /* must not be NULL */
    int (*on_insert) (void *value);        /* may be NULL */
    int (*on_insert_exists) (void *old, void *value); /* may be NULL */
    int (*on_remove) (void *value);        /* may be NULL */
};

static inline int rho_bintree_on_insert_nop(void *value) { (void)value; return (0); }
static inline int rho_bintree_on_insert_exists_nop(void *old, void *value) { (void)old; (void)value; return (0); }
static inline int rho_bintree_on_remove_nop(void *value) { (void)value; return (0); }

struct rho_bintree_node {
    void * value; 
    struct rho_bintree_node *left;
    struct rho_bintree_node *right;
};

struct rho_bintree {
    struct rho_bintree_ops *ops;
    struct rho_bintree_node *root;
};

struct rho_bintree_node * rho_bintree_node_create(void *value);
void rho_bintree_node_destroy(struct rho_bintree_node *node);

struct rho_bintree * rho_bintree_create(struct rho_bintree_ops *ops);
void rho_bintree_destroy(struct rho_bintree *bintree);

int rho_bintree_insert(struct rho_bintree *bintree, void *value);
void * rho_bintree_min(const struct rho_bintree *bintree);
void * rho_bintree_max(const struct rho_bintree *bintree);
void * rho_bintree_search(const struct rho_bintree *bintree, void *value);
void * rho_bintree_remove(struct rho_bintree *bintree, void *value);

void rho_bintree_traverse_inorder(const struct rho_bintree *bintree,
        bool (*cb) (void * value, void *user), void *user);

#endif /* ! _RHO_BINTREE_H_ */
