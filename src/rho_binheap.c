/* A heap is a binary three that is completely filled, with the possible
 * exception of the bottom lelve, which is filled form left to right.  Such a
 * tree is known as a complete binary tree.
 *
 * Heap order property: for every node X, the key in the parent of X is smaller
 * than (or equal to ) the key in X, with the obvious excpetion of the root
 * (which has no parent).  In other words, any node should be smaller than all
 * of its descendants, and, as a result, the root contains the mallest value.
 *
 * for any elemnt in position i:
 *
 *  - the left child is in position 2i
 *  - the rigth child in in positiion 2i + 1
 *  - the pasrent is in position floor(i/2)
 */
struct rho_binheap *
rho_binheap_create(int init_cap)
{
    struct rho_binheap *binheap = NULL;

    RHO_ASSERT(init_cap > 0);

    binheap = rhoL_zalloc(sizeof(*binheap));
    binheap->elems = rhoL_zalloc(init_cap * sizeof(void *));
    binheap->init_cap = init_cap;

    return (binheap);
}

void
rho_binheap_destroy(struct rho_binheap *binheap)
{

}

void 
rho_binheap_insert(struct rho_binheap *binheap, void *elem)
{

}

void *
rho_binheap_removemin(struct rho_binheap *binheap)
{

}
