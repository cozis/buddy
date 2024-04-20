#include <stddef.h>
#include <stdint.h>

#define BUDDY_ALLOC_MAX_BLOCK_LOG2 13
#define BUDDY_ALLOC_MIN_BLOCK_LOG2 3

_Static_assert(BUDDY_ALLOC_MIN_BLOCK_LOG2 <= BUDDY_ALLOC_MAX_BLOCK_LOG2);
_Static_assert(BUDDY_ALLOC_MIN_BLOCK_LOG2 > 2);

#define BUDDY_ALLOC_NUM_LISTS (BUDDY_ALLOC_MAX_BLOCK_LOG2 - BUDDY_ALLOC_MIN_BLOCK_LOG2 + 1)

// To keep track of the allocation state of a page,
// we need one bit for each possible block that can
// be made out of it. For instance, if the page can
// only be allocated in its entirety, 1 bit is required.
// If the blocks halfs can be allocated too, 3 bits
// are required: 1 for the page, 1 for the frist half
// and 1 for the second half. Allowing the allocation
// of page quarters requires 4 more bits, for a total
// of 7. In general, if we allow splitting a page N
// times (N=0 means only the entire page can be allocated),
// then 2^(N+1)-1 bits are necessary.
#define BUDDY_ALLOC_BITS_PER_PAGE ((1U << (BUDDY_ALLOC_NUM_LISTS)) - 1)
#define BUDDY_ALLOC_WORDS_PER_PAGE ((BUDDY_ALLOC_BITS_PER_PAGE + 31) / 32)

struct page_info {
    uint32_t bits[BUDDY_ALLOC_WORDS_PER_PAGE];
};

struct buddy_alloc {
    void *base;
    void *lists[BUDDY_ALLOC_NUM_LISTS];
    struct page_info *info;
    int num_info;
};

struct buddy_alloc buddy_startup(char *base, size_t size, struct page_info *page_info, int num_page_info);
void               buddy_cleanup(struct buddy_alloc *alloc);
void              *buddy_malloc (struct buddy_alloc *alloc, size_t len);
void               buddy_free   (struct buddy_alloc *alloc, size_t len, void *ptr);
