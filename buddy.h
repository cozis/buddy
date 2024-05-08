#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* === INTRODUCTION ===
 * This is the implementation of a general purpose allocator that uses 
 * the "buddy system". It uses a pool of memory specified by the user
 * and allows allocations up to a specified threshold.
 * 
 * === THE BUDDY SYSTEM ===
 * The buddy system is an allocator that puts memory regions available
 * for allocation in buckets based on their size. Each bucket contains
 * regions of a different power of 2. When the user request the allocation
 * of a region of a given length, the allocator looks for an unused
 * region from the appropriate bucket (the one containing the smallest
 * regions that aren't smaller of the requested size) and returns it.
 * If the bucket is empty, the allocator gets one from the list of larger
 * blocks and splits it. One half is returned to the user and the other
 * is put in the bucket. These two blocks that were split from one larger
 * block are called "buddies". When deallocating a block, the allocator
 * checks if its "buddy" is currently used. If it's not, it merges the
 * buddies and puts the larger block in the bucket. If the buddy is used,
 * only the region provided by the user is put in the bucket. This mechanism
 * is recursive, so if two buddies of size N can be merged, the allocator
 * now looks for the buddy of size 2N and so on until either a buddy is
 * in use or it got to the largest block possible. The same goes for the
 * allocation code.
 */


/*
 * This is the minimum and maximum block size. The allocator uses doubly
 * linked free lists to keep track of unused blocks, so a block must be
 * at least the size of two pointers. We assume a pointer is 8 bytes long,
 * so the minimum value must be greater or equal to 4 (log2(2*8) = 4).
 * 
 * For the maximum value there is really no downside in making it big,
 * except for the fact that the pool provided by the user should at
 * least be that big.
 */
#define BUDDY_ALLOC_MAX_BLOCK_LOG2 13
#define BUDDY_ALLOC_MIN_BLOCK_LOG2 4

_Static_assert(BUDDY_ALLOC_MIN_BLOCK_LOG2 <= BUDDY_ALLOC_MAX_BLOCK_LOG2);
_Static_assert(BUDDY_ALLOC_MIN_BLOCK_LOG2 > 3);

#define BUDDY_ALLOC_NUM_LISTS (BUDDY_ALLOC_MAX_BLOCK_LOG2 - BUDDY_ALLOC_MIN_BLOCK_LOG2 + 1)
#define BUDDY_ALLOC_MAX_BLOCK_SIZE (1U << BUDDY_ALLOC_MAX_BLOCK_LOG2)
#define BUDDY_ALLOC_MIN_BLOCK_SIZE (1U << BUDDY_ALLOC_MIN_BLOCK_LOG2)

/*
 * To keep track of the allocation state of a page,
 * we need one bit for each possible block that can
 * be made out of it. For instance, if the page can
 * only be allocated in its entirety, 1 bit is required.
 * If the blocks halfs can be allocated too, 3 bits
 * are required: 1 for the page, 1 for the frist half
 * and 1 for the second half. Allowing the allocation
 * of page quarters requires 4 more bits, for a total
 * of 7. In general, if we allow splitting a page N
 * times (N=0 means only the entire page can be allocated),
 * then 2^(N+1)-1 bits are necessary.
 */
#define BUDDY_ALLOC_BITS_PER_PAGE ((1U << (BUDDY_ALLOC_NUM_LISTS)) - 1)
#define BUDDY_ALLOC_WORDS_PER_PAGE ((BUDDY_ALLOC_BITS_PER_PAGE + 31) / 32)
struct page_info {
    uint32_t bits[BUDDY_ALLOC_WORDS_PER_PAGE];
};

struct buddy_page {
    struct buddy_page *prev;
    struct buddy_page *next;
};

struct buddy_alloc {
    void  *base;
    size_t size;
    struct buddy_page *lists[BUDDY_ALLOC_NUM_LISTS];
    struct page_info *info;
    int num_info;
};

/*
 * Initialize the allocator.
 *
 * The allocator will use as allocation memory the [size]
 * bytes as position [base]. If the memory pool isn't
 * aligned to BUDDY_ALLOC_MAX_BLOCK_SIZE, the first bytes
 * are discarded.
 * 
 * The user needs to provide the allocator with an array
 * of [struct page_info] with a capacity equal to the number
 * of (aligned) BUDDY_ALLOC_MAX_BLOCK_SIZE blocks in the
 * pool. If less page_info structs are provided than necessary
 * for the pool, the exceeding portion of the pool is
 * discarded.
 */
struct buddy_alloc buddy_startup(char *base, size_t size, struct page_info *page_info, int num_page_info);

/*
 * Deinitialize the allocator.
 */
void buddy_cleanup(struct buddy_alloc *alloc);

/*
 * Allocate a memory region of size [len]. If allocation
 * fails, NULL is returned.
 */
void *buddy_malloc(struct buddy_alloc *alloc, size_t len);

/*
 * Deallocate a memory region allocated using [buddy_malloc].
 * The [len] argument must be the same value passed when
 * allocating.
 */
void buddy_free(struct buddy_alloc *alloc, size_t len, void *ptr);

bool buddy_owned(struct buddy_alloc *alloc, void *ptr);

bool buddy_allocated(struct buddy_alloc *alloc, void *ptr, size_t len);