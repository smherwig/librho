#include <stdbool.h>

#include "rho_bintree.h"
#include "rho_log.h"
#include "rho_mem.h"

struct rho_avltree_node *
rho_avltree_node_create(void *value)
{
    struct rho_avltree_node *node = NULL;
    node = rhoL_zalloc(sizeof(*node));
    node->value = value;
    return (node);
}

struct rho_avltree *
rho_avltree_create(struct rho_avltree_ops *ops)
{
    struct rho_avltree *avltree = NULL;
    bintree = rhoL_zalloc(sizeof(*avltree));
    bintree->ops = ops;
    return (bintree);
}
