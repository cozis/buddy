#ifndef BUDDY_ALLOC_H
#define BUDDY_ALLOC_H

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
#define BUDDY_ALLOC_MAX_BLOCK_LOG2 12
#define BUDDY_ALLOC_MIN_BLOCK_LOG2 4

_Static_assert(BUDDY_ALLOC_MIN_BLOCK_LOG2 <= BUDDY_ALLOC_MAX_BLOCK_LOG2);
_Static_assert(BUDDY_ALLOC_MIN_BLOCK_LOG2 > 3);

/*
 * Handle to the allocator
 */
struct buddy;

/*
 * Initialize the allocator. If not enough memory was provided,
 * NULL is returned. NULL is considered to be a valid allocator
 * handle, representing the empty allocator.
 */
struct buddy *buddy_startup(char *base, size_t size);

/*
 * Allocate a memory region of size [len]. If allocation
 * fails, NULL is returned.
 */
void *buddy_malloc(struct buddy *alloc, size_t len);

/*
 * Deallocate a memory region allocated using [buddy_malloc].
 * The [len] argument must be the same value passed when
 * allocating.
 */
void buddy_free(struct buddy *alloc, size_t len, void *ptr);

/*
 * Returns true if and only if ptr points inside of the memory
 * generally available for allocation (even if currently marked
 * as allocated).
 */
bool buddy_owned(struct buddy *alloc, void *ptr);

/*
 * Returns true if and only if the block at address ptr of size
 * len is owned by the allocator and marked as allocated.
 */
bool buddy_allocated(struct buddy *alloc, void *ptr, size_t len);

void *buddy_get_base(struct buddy *alloc);

#endif