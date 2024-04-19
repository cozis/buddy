#include <stddef.h>
#include <stdint.h>

struct buddy_alloc {
    void *base;
    void *lists[5];
    uint32_t *bitsets;
    int num_bitsets;
};

void init_buddy_alloc(struct buddy_alloc *alloc,
                      char *base, size_t size,
                      uint32_t *bitsets, int num_bitsets);

void free_buddy_alloc(struct buddy_alloc *alloc);

void *buddy_malloc(struct buddy_alloc *alloc,
                   size_t len);

void buddy_free(struct buddy_alloc *alloc,
                void *ptr, size_t len);

bool buddy_allocated(struct buddy_alloc *alloc,
                     void *ptr, size_t len);