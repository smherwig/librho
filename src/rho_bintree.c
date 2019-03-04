#include <stdbool.h>

#include "rho_bintree.h"
#include "rho_log.h"
#include "rho_mem.h"

struct rho_bintree_node *
rho_bintree_node_create(void *value)
{
    struct rho_bintree_node *node = NULL;
    node = rhoL_zalloc(sizeof(*node));
    node->value = value;
    return (node);
}

void
rho_bintree_node_destroy(struct rho_bintree_node *node)
{
    /* TODO */
}

struct rho_bintree *
rho_bintree_create(struct rho_bintree_ops *ops)
{
    struct rho_bintree *bintree = NULL;
    bintree = rhoL_zalloc(sizeof(*bintree));
    bintree->ops = ops;
    return (bintree);
}

void
rho_bintree_destroy(struct rho_bintree *bintree)
{
    /* TODO: walk the tree */
    rhoL_free(bintree);
}

void *
rho_bintree_min(const struct rho_bintree *bintree)
{
    const struct rho_bintree_node *node = NULL;

    RHO_ASSERT(bintree != NULL);

    node = bintree->root;

    if (node == NULL)
        return (NULL);

    while (node->left != NULL)
        node = node->left;
    return (node->value);
}

void *
rho_bintree_max(const struct rho_bintree *bintree)
{
    const struct rho_bintree_node *node = NULL;

    RHO_ASSERT(bintree != NULL);

    node = bintree->root;

    if (node == NULL)
        return (NULL);
    
    while (node->right != NULL)
        node = node->right;
    return (node->value);
}

int
rho_bintree_insert(struct rho_bintree *bintree, void *value)
{
    int ret = 0;
    struct rho_bintree_node *node = NULL;

    RHO_ASSERT(bintree != NULL);
    RHO_ASSERT(value != NULL);

    if (bintree->root == NULL) {
        bintree->root = rho_bintree_node_create(value);
        return (bintree->ops->on_insert(value));
    }

    node = bintree->root;
    while (1) {
        ret = bintree->ops->cmp(value, node->value);
        if (ret < 0) {
            if (node->left == NULL) {
                node->left = rho_bintree_node_create(value);
                return (bintree->ops->on_insert(value));
            } else {
                node = node->left;
            }
        } else if (ret > 0) {
            if (node->right == NULL) {
                node->right = rho_bintree_node_create(value);
                return (bintree->ops->on_insert(value));
            } else {
                node = node->right;
            }
        } else {
            return (bintree->ops->on_insert_exists(node->value, value));
        }
    }
}

void *
rho_bintree_search(const struct rho_bintree *bintree, void *needle)
{
    int ret = 0;
    const struct rho_bintree_node *node = NULL;

    RHO_ASSERT(bintree != NULL);

    if (bintree->root == NULL)
        return (NULL);

    node = bintree->root;
    do {
        ret = bintree->ops->cmp(needle, node->value);
        if (ret < 0)
            node = node->left;
        else if (ret > 0)
            node = node->right;
        else 
            break;
    } while (node != NULL);

    return (node->value);
}

bool
rho_bintree_empty(const struct rho_bintree *bintree)
{
    RHO_ASSERT(bintree != NULL);
    return (bintree->root == NULL);
}

bool
rho_bintree_node_is_leaf(const struct rho_bintree_node *node)
{
    RHO_ASSERT(node != NULL);
    return (node->left == NULL && node->right == NULL);
}

enum rho_bintree_which {
    RHO_BINTREE_LEFT,
    RHO_BINTREE_RIGHT
};

static int
rho_bintree_node_num_children(const struct rho_bintree_node *node)
{
    int nchildren = 0;

    RHO_ASSERT(node != NULL);

    if (node->left != NULL)
        nchildren++;
    if (node->right != NULL)
        nchildren++;

    return (nchildren);
}

void *
rho_bintree_remove(struct rho_bintree *bintree, void *value)
{
    struct rho_bintree_node *node = NULL;
    struct rho_bintree_node *parent = NULL;
    struct rho_bintree_node *minright = NULL;
    int ret = 0;
    int nchildren = 0;
    void *retval = NULL;
    enum rho_bintree_which which = RHO_BINTREE_LEFT;

    RHO_ASSERT(bintree != NULL);
    RHO_ASSERT(value != NULL);

    if (rho_bintree_empty(bintree))
        return (NULL);

    /* find matching node and track parent */
    node = bintree->root;
    parent = node;
    do {
        ret = bintree->ops->cmp(value, node->value);
        if (ret < 0) {
            parent = node;
            node = node->left;
            which = RHO_BINTREE_LEFT;
        } else if (ret > 0) {
            parent = node;
            node = node->right;
            which = RHO_BINTREE_RIGHT;
        } else {
            break;
        }
    } while (node != NULL);

    /* node not found */
    if (node == NULL)
        return (NULL);

    /* root */
    if (node == parent) {
        retval = node->value;
        bintree->ops->on_remove(value);
        rho_bintree_node_destroy(node);
        bintree->root = NULL;
        return (retval);
    }

    retval = node->value;
    nchildren = rho_bintree_node_num_children(node);
    switch (nchildren) {
    case 0:
        if (which == RHO_BINTREE_LEFT)
            parent->left = NULL;
        else
            parent->right = NULL;
        break;
    case 1:
        /* cut node from tree and link child to parent */
        if (which == RHO_BINTREE_LEFT) 
            if (node->left != NULL)
                parent->left = node->left;
            else
                parent->left = node->right;
        else
            if (node->left != NULL)
                parent->right = node->left;
            else
                parent->right = node->right;
        break;
    case 2:
        /* find the minimum value of the right subtree and
         * replace the node with this value
         */
        minright = node->right;
        while (minright->left != NULL)
            minright = minright->left;
        node->value = minright->value;
        rho_bintree_node_destroy(node);
        break;
    default:
        RHO_ASSERT(false);
    }

    bintree->ops->on_remove(retval);
    rho_bintree_node_destroy(node);
    return (retval);
}

static void
rho_bintree_node_traverse_inorder(const struct rho_bintree_node *node,
        bool (*cb) (void *value, void *user), void *user)
{
    if (node == NULL)
        return;

    rho_bintree_node_traverse_inorder(node->left, cb, user);
    cb(node->value, user);
    rho_bintree_node_traverse_inorder(node->right, cb, user);
}

void
rho_bintree_traverse_inorder(const struct rho_bintree *bintree,
        bool (*cb) (void *value, void *user), void *user)
{
    RHO_ASSERT(bintree != NULL);
    RHO_ASSERT(cb != NULL);

    rho_bintree_node_traverse_inorder(bintree->root, cb, user);
}
