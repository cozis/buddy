/* === BIT MAGIC ========================================================
 * Bit stuff required to understand the code:
 *
 *     1. Division and multiplication using shifts
 *
 *        It is possible to perform multiplication and division by
 *        a power of 2 using shift operations.
 *
 *        Starting by the simple case, the binary representation
 *        of 1 and 2 is:
 *
 *            x = 0000 0001
 *            y = 0000 0010
 *
 *        So 2 is 1 shifted left by 1. It's pretty intuitive that
 *        this works for any power of 2. Shifting left by 1 equals
 *        multiplying by 2. Shifting by more than 1 has the effect
 *        of multiplying by a power of 2 with the shift amount as
 *        exponent.
 *
 *        For values that aren't powers of 2, we can see them as
 *        sums of such powers:
 *
 *            453 = 0000 0001 1100 0101
 *                = 2^0 + 2^2 + 2^6 + 2^7 + 2^8
 *                = (1 << 0) + (1 << 2) + (1 << 6) + (1 << 7) + (1 << 8)
 *
 *        Multiplying by 2, each power of 2 that makes up the value
 *        shifts by 1, making the entire value shift too. Here is
 *        the proof:
 *        
 *            2 * 453 = 2 * (2^0 + 2^2 + 2^6 + 2^7 + 2^8)
 *                    = 2 * ((1 << 0) + (1 << 2) + (1 << 6) + (1 << 7) + (1 << 8))
 *                    = ((1 << 0) + (1 << 2) + (1 << 6) + (1 << 7) + (1 << 8)) << 1
 *                    = (1 << (0 + 1)) + (1 << (2 + 1)) + (1 << (6 + 1)) + (1 << (7 + 1)) + (1 << (8 + 1))
 *                    = ((1 << 1) + (1 << 3) + (1 << 7) + (1 << 8) + (1 << 9))
 *                    = 0000 0011 1000 1010
 *        
 *        So this works for all values. Similarly, shifting right
 *        divides by 2.
 *
 *
 *     2. Modulo using bitwise ands
 * 
 *        The modulo operator returns the remainder of the division:
 * 
 *            104 % 10 = 4
 * 
 *        When the right operand is a power of the base the two numbers
 *        are represented in, getting the result is easy. In base 10 this
 *        works when the right operand is 10, 100, 1000, etc. If N is the
 *        number of zeros of the right operand, the remainder is the number
 *        made by the lower N digits of the left operand. For instance:
 * 
 *            435430598 % 1000 = 598
 *        
 *        This works the same way in base 2 when the right operand is a
 *        power of 2:
 *        
 *            10001011010 % 100 = 10
 *            10001011010 % 10000 = 1010
 *        
 *        In base 2 getting the lower N digits is very easy and can be
 *        done using a mask with a bitwise and operation. The mask can
 *        be calculate subtracting 1 by the right operand:
 *
 *            100-1 = 011
 *            10000-1 = 01111
 * 
 *        So finally, when the right operand is a power of 2:
 * 
 *            x % y == x & (y - 1)
 *
 *
 *     3. Check if a word is a power of 2.  A power of 2 has only
 *        one high bit:
 * 
 *            x = 0000 0100
 * 
 *        Subtracting 1 from it will result in the only high bit to
 *        become 0 and all of the lower 0 to become 1.
 *        to become 1 and:
 * 
 *            y = x - 1 = 0000 0011
 * 
 *        This makes it so x and y share no high bits and the 
 *        bitwise "and" operation is 0.
 * 
 *        On the other hand, for something other than a power of 2
 *        at least 2 bits are high. Subtracting 1 will lower the least
 *        significant bit but keep the most significant ones:
 * 
 *            z = 0100 0100
 *            w = z - 1 = 0100 0011
 * 
 *        So z and w will share at least one high bit. The bitwise
 *        "and" operation is never zero for something that's not a
 *        power of 2.
 * 
 *        In conclusion, we can test a power of 2 using:
 * 
 *            n & (n - 1) == 0
 * 
 * 
 *     4. Aligning to power of 2 boundary
 * 
 *        Given an integer x, we call it "aligned to y" when it's
 *        a multiple of y. Sometimes we need a way to calculate
 *        the first integer aligned to a boundary that comes a
 *        given number.
 * 
 *        Calculating ho far the integer is from the last boundary
 *        is possible using the modulo operator
 * 
 *            delta_from_last_boundary = x % boundary
 *        
 *        therefore we can calculate the distance from the following
 *        boundary by doing:
 * 
 *            delta_from_next_boundary = boundary - delta_from_last_boundary
 *                                     = boundary - x % boundary
 * 
 *        There is also one other and faster way. Lets say x is a
 *        positive number lower than boundary, therefore the last
 *        boundary is 0 and the next is boundary exactly.
 * 
 *                                     last boundary
 *                                     |          next boundary
 *                                     v          v
 *            - -- --- -----+----------+-------x--+----- --- -- -
 *                         -B          0          B
 * 
 *        Negating x, the distance from the two boundaries is inverted:
 *
 *                          last boundary
 *                          |          next boundary
 *                          v          v
 *            - -- --- -----+--y-------+----------+----- --- -- -
 *                         -B          0          B
 * 
 *                                   y = -x
 * 
 *        So we can get the distance from the next boundary from x
 *        calculating the modulo on -x.
 * 
 *            delta_from_next_boundary = -x % boundary
 * 
 *        When the boundary is a power of 2, the modulo can be calculated
 *        using a bitwise and:
 * 
 *            delta_from_next_boundart = -x & (boundary - 1)
 * 
 * === THE BIT TREE =====================================
 * The state of each block is tracked by one bit. If the
 * bit is set, the block is allocated else it is free.
 * This is necessary to catch any invalid free operations
 * the user may perform.
 * 
 * Blocks are caracterized by their address and length,
 * so for instance if we consider the block at address P
 * of size N and the block at the same address P but size
 * 2N, these two are considered different and therefore
 * each has its own state bit.
 * 
 * It is possible to organize blocks in a binary tree
 * structure. Since each bit is associated to one and only
 * one block, the same goes for the bits. This allocator
 * stores the tree of bits breadth first in the page_info
 * structures. Each page_info structure holds all the bits
 * necessary to keep track of the splits of one block with
 * the maximum size.
 * 
 * If this tree thing isn't clear, here is an example:
 * 
 *     Lets say the allocator is configured to handle 2 blocks
 *     of 1024 that can be split up to 2 times:
 * 
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *         |         1024          |         1024          |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 * 
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *         |    512    |    512    |    512    |    512    |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 * 
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *         | 256 | 256 | 256 | 256 | 256 | 256 | 256 | 256 |
 *         +-----+-----+-----+-----+-----+-----+-----+-----+
 *
 *     Don't see the tree yet?
 *
 *                  1024               1024
 *                 /    \             /    \
 *              512      512       512      512
 *              / \      / \       / \      / \
 *            256 256  256 256   256 256  256 256
 *
 *     Now about the tree of bits..
 * 
 *     The bits are serialized this way:
 * 
 *         index  size
 * 
 *             1  1K
 *             2   512
 *             3   512
 *             4    256
 *             5    256
 *             6    256
 *             7    256
 * 
 *             1  1K
 *             2   512
 *             3   512
 *             4    256
 *             5    256
 *             6    256
 *             7   256
 *     
 *     The group of bits of a block are stored breadth first,
 *     while the groups themselves are stored linearly.
 * 
 *     I added 1-based indices within each group to show how
 *     the first chunk of its size class is always located at
 *     an index that's a power of 2:
 * 
 *         1K  -> 2^0
 *         512 -> 2^1
 *         256 -> 2^2
 * 
 *     But the block sizes are also powers of 2:
 * 
 *         2^10       -> 2^0
 *         2^(10 - 1) -> 2^1
 *         2^(10 - 2) -> 2^2
 * 
 *     In general the first block of size 2^(10-i) is associated
 *     to the bit at index 2^i of its group. The 10 is there
 *     because its the maximum block size log2. By generalizing
 *     the maximum block size we get this:
 *  
 *         2^(max_block_size_log2 - N)  ->  2^N
 *
 *     But this only brings us half way, because it gets us the
 *     bit of the first block of the given size, but not the one
 *     we need!
 * 
 *     The bits of a size class are stored linearly so we just
 *     need to add the index of the block relative to the start
 *     of the memory pool. If we are looking for the bit for the
 *     block at address P of size 2^(max_block_size_log2 - N),
 *     and the pool starts at address B, then the block index is:
 * 
 *         (P - B) / 2^(max_block_size_log2 - N)
 * 
 *     So the index of the bit within the group is:
 * 
 *         2^(max_block_size_log2 - N)  ->  2^N + (P - B) / 2^(max_block_size_log2 - N)
 * 
 *     Since every value here is a power of 2, all divisions,
 *     logarithms and powers can be evaluated as shifts:
 * 
 *         1 << (max_block_size_log2 - N)  ->  (1 << N) + ((P - B) >> (max_block_size_log2 - N))
 *
 */

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "buddy.h"

/*
 * Just for convenience
 */
#define MAX_BLOCK_LOG2 BUDDY_ALLOC_MAX_BLOCK_LOG2
#define MIN_BLOCK_LOG2 BUDDY_ALLOC_MIN_BLOCK_LOG2
#define MAX_BLOCK_SIZE BUDDY_ALLOC_MAX_BLOCK_SIZE
#define MIN_BLOCK_SIZE BUDDY_ALLOC_MIN_BLOCK_SIZE
#define MAX_BLOCK_ALIGN_MASK (MAX_BLOCK_SIZE - 1)

/*
 * Gets the address of the i-th page of the memory pool.
 * In this context, a page is a block of size MAX_BLOCK_SIZE.
 */
static struct buddy_page*
page_index_to_ptr(char *base, int i)
{
    return (struct buddy_page*) (base + (i << MAX_BLOCK_LOG2));
}

static struct buddy_alloc startup_empty()
{
    struct buddy_alloc alloc;
    alloc.base = NULL;
    alloc.size = 0;
    alloc.info = NULL;
    alloc.num_info = 0;
    for (int i = 0; i < BUDDY_ALLOC_NUM_LISTS; i++)
        alloc.lists[i] = NULL;
    return alloc;
}

/*
 * See buddy.h
 */
struct buddy_alloc buddy_startup(char *base, size_t size,
                                 struct page_info *info,
                                 int num_info)
{
    if (base == NULL || info == NULL)
        return startup_empty();

    /*
     * Calculate the padding necessary to align the base pointer
     * to MAX_BLOCK_SIZE. If the padding is greater than the size
     * of the pool not even one aligned page was provided so the
     * allocator is basically empty.
     */
    size_t pad = -(uintptr_t) base & MAX_BLOCK_ALIGN_MASK;

    if (pad > size)
        return startup_empty();

    base += pad;
    size -= pad;

    /*
     * Discard any bites from the end of the pool that don't
     * make up an entire block.
     */
    size_t rem = size & MAX_BLOCK_ALIGN_MASK;
    size -= rem;

    /*
     * Discard blocks for which there isn't a page_info structure.
     */
    size_t max_bytes = (size_t) num_info << MAX_BLOCK_LOG2;
    if (size > max_bytes)
        size = max_bytes;

    /*
     * Make the linked list of pages
     */
    struct buddy_page *head = NULL;
    struct buddy_page *tail = NULL;
    int num_pages = size >> MAX_BLOCK_LOG2;
    for (int i = 0; i < num_pages; i++) {

        struct buddy_page *p = page_index_to_ptr(base, i);

        if (head) {
            tail->next = p;
            p->prev = tail;
        } else {
            head = p;
            p->prev = NULL;
        }
        tail = p;
        p->next = NULL;
    }

    /*
     * Initialize the page info. The page_info bits are 0 when
     * blocks are unused, so they start at zero.
     */
    assert(info);
    memset(info, 0, num_info * sizeof(struct page_info));

    struct buddy_alloc alloc;
    alloc.base = base,
    alloc.size = size;
    alloc.info = info;
    alloc.num_info = num_info;

    // All lists are empty except for the one of larger chunks
    for (int i = 0; i < BUDDY_ALLOC_NUM_LISTS-1; i++)
        alloc.lists[i] = NULL;
    alloc.lists[BUDDY_ALLOC_NUM_LISTS-1] = head;

    return alloc;
}

/*
 * See buddy.h
 */
void buddy_cleanup(struct buddy_alloc *alloc)
{
    (void) alloc;
}

/*
 * Returns true iff n is a power of 2. To understand how this works,
 * refer to the comment at start of the file. 
 */
static bool is_pow2(size_t n)
{
    return (n & (n-1)) == 0;
}

/*
 * Returns the first power of 2 that comes after v, of v if its
 * already a power of 2.
 */
static size_t round_pow2(size_t v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    if (sizeof(v) > 4)
        v |= v >> 32;
    v++;
    return v;
}

/*
 * Returns the index of the first set bit of x. The index of the
 * least significant bit is 0. If no bit is set, the result is -1.
 */
static int first_set(size_t x)
{
    size_t y;
    size_t z;
    size_t t;
    int i;

    // First check that at least one bit is set
    if (x == 0) return -1;

    // Subtracting 1 from x lowers the less significan bit and
    // sets all zeros that come before it:
    //
    //     x   = 1010 0100
    //     x-1 = 1010 0011
    //
    // So and-ing x and x-1 removes the less significant bit
    // of x:
    //
    //     x         = 1010 0100
    //     x & (x-1) = 1010 0000
    //
    // Subtracting from x its version without the lower bit,
    // leavs that bit only. 
    y = x & (x - 1);
    z = x - y;

    // At this point z has the less significant bit set only,
    // and we need to find its index. We do so with a binary
    // search, which requires a number of "steps" equal to the
    // log2 of the number of bits in x. Each step consists of
    // testing the upper half of the bit group and, if the test
    // is positive and the upper half contains the set bit, add
    // to the index the half the number of bits of the group
    // and swap the low half with the high half. This is done
    // until down to 8 bits. The last byte is done using a table.
    i = 0;

    // The size_t can be 8 or 4 bytes. If it's 8 bytes we need
    // to do one more step.
    if (sizeof(size_t) > 4) {
        t = z >> 32;
        if (t) {
            i += 32;
            z = t;
        }
    }

    t = z >> 16;
    if (t) {
        i += 16;
        z = t;
    }

    t = z >> 8;
    if (t) {
        i += 8;
        z = t;
    }

    // Table associating all powers of 2 lower than 256 and their
    // logarithm, which is also the index of the set bit.
    static const unsigned char table[] = {
        0, 0, 1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    i += table[z];

    return i;
}

static size_t page_index(struct buddy_alloc *alloc, void *ptr)
{
    uintptr_t x = (uintptr_t) ptr;
    uintptr_t y = (uintptr_t) alloc->base;
    assert(x >= y);
    return (x - y) >> MAX_BLOCK_LOG2;
}

static size_t block_info_index(void *ptr, size_t len)
{
    int len_log2 = first_set(len);
    size_t reloff = ((uintptr_t) ptr) & MAX_BLOCK_ALIGN_MASK;
    return (1U << (MAX_BLOCK_LOG2 - len_log2)) + (reloff >> len_log2);
}

/*
 * This function checks wether the block (ptr, len)
 * was marked as allocated.
 * 
 * See the set_allocated function
 */
static bool is_allocated(struct buddy_alloc *alloc,
                         void *ptr, size_t len)
{
    assert(is_pow2(len));

    size_t i = page_index(alloc, ptr);
    size_t j = block_info_index(ptr, len);

    int bits_per_word_log2 = 5;
    int bits_per_word = 1 << bits_per_word_log2;

    int u = j >> bits_per_word_log2;
    int v = j & (bits_per_word - 1);

    uint32_t mask = 1U << v;

    return (alloc->info[i].bits[u] & mask) == mask;
}

/*
 * This function marks the block (ptr, len) as allocated.
 * Note that a block is considered to be different from
 * its splits. For instance when the block (ptr, len/2)
 * is marked as allocated, the block (ptr, len) isn't.
 * 
 * For more info about how allocation state is tracked,
 * refer to the explanation THE BIT TREE at the start of
 * the file.
 */
static void set_allocated(struct buddy_alloc *alloc,
                          void *ptr, size_t len, bool value)
{
    assert(is_pow2(len));

    size_t i = page_index(alloc, ptr);
    size_t j = block_info_index(ptr, len);

    size_t bits_per_word_log2 = 5;
    size_t bits_per_word = 1 << bits_per_word_log2;

    size_t u = j >> bits_per_word_log2;
    size_t v = j & (bits_per_word - 1);

    assert(i < (size_t) alloc->num_info);
    assert(u < BUDDY_ALLOC_WORDS_PER_PAGE);

    uint32_t mask = 1U << v;
    if (value)
        alloc->info[i].bits[u] |= mask;
    else
        alloc->info[i].bits[u] &= ~mask;
}

/*
 * This function returns true if the block (ptr, len)
 * or any of its splits are marked as allocated.
 */
static bool
is_allocated_considering_splits(struct buddy_alloc *alloc,
                                char *ptr, size_t len)
{
    if (len == MIN_BLOCK_SIZE)
        return is_allocated(alloc, ptr, len);

    char *sib = ptr + (len >> 1);
    return is_allocated(alloc, ptr, len)
        || is_allocated_considering_splits(alloc, ptr, len >> 1)
        || is_allocated_considering_splits(alloc, sib, len >> 1);
}

static size_t normalize_len(size_t len)
{
    if (len == 0)
        return 0;

    if (len < MIN_BLOCK_SIZE)
        return MIN_BLOCK_SIZE;

    return round_pow2(len);
}

static int list_index_for_size(size_t len)
{
    int i = first_set(len);
    return i - MIN_BLOCK_LOG2;
}

// Get the sibling block of the one at position "ptr". If the block
// is aligned at double its size, the sibling is "len" bytes after
// it, else its len bytes before.
static char *sibling_of(char *ptr, size_t len)
{
    assert(is_pow2(len));

    // There is no such thing as a sibling of a page
    assert(len < MAX_BLOCK_SIZE);

    if (((uintptr_t) ptr & ((len << 1) - 1)) == 0)
        return ptr + len;
    else
        return ptr - len;
}

static char *parent_of(char *ptr, size_t len)
{
    char *sib = sibling_of(ptr, len);
    if ((uintptr_t) sib < (uintptr_t) ptr)
        return sib;
    else
        return ptr;
}

static bool
sibling_allocated_considering_splits(struct buddy_alloc *alloc,
                  void *ptr, size_t len)
{
    char *sib = sibling_of(ptr, len);
    return is_allocated_considering_splits(alloc, sib, len);
}

static void
remove_sibling_from_list(struct buddy_alloc *alloc,
                         int i, void *ptr)
{
    size_t len = 1U << (i + MIN_BLOCK_LOG2);
    struct buddy_page *sibling = (struct buddy_page*) sibling_of(ptr, len);

    if (sibling->prev)
        sibling->prev->next = sibling->next;
    else
        alloc->lists[i] = sibling->next;
    
    if (sibling->next)
        sibling->next->prev = sibling->prev;
}

/*
 * Append the chunk at "ptr" to the i-th list.
 * The size of the block can be calculated as:
 * 
 *     len = 1 << (i + MIN_BLOCK_LOG2)
 * 
 */
static void append(struct buddy_alloc *alloc,
                   int i, void *ptr)
{
    assert(i >= 0 && i < BUDDY_ALLOC_NUM_LISTS);
    
    struct buddy_page *page = ptr;

    if (alloc->lists[i])
        alloc->lists[i]->prev = page;

    page->prev = NULL;
    page->next = alloc->lists[i];

    alloc->lists[i] = page;
}

static char *pop(struct buddy_alloc *alloc, int i)
{
    assert(i >= 0 && i < BUDDY_ALLOC_NUM_LISTS);

    struct buddy_page *page = alloc->lists[i];
    assert(page);

    alloc->lists[i] = page->next;
    if (alloc->lists[i])
        alloc->lists[i]->prev = NULL;

    return (char*) page;
}

void *buddy_malloc(struct buddy_alloc *alloc, size_t len)
{    
    if (len == 0 || len > MAX_BLOCK_SIZE) 
        return NULL;
    if (alloc->base == NULL)
        return NULL;
    len = normalize_len(len);
    assert(len >= MIN_BLOCK_SIZE);

    // Index of the list of blocks with size "len"
    int i = list_index_for_size(len);
    assert(i >= 0 && i < BUDDY_ALLOC_NUM_LISTS);

    // Get the index of the first non-empty list
    int j = i;
    while (j < BUDDY_ALLOC_NUM_LISTS && alloc->lists[j] == NULL)
        j++;

    // If the index went over the list of full pages
    // then the allocator can't handle this allocation.
    if (j == BUDDY_ALLOC_NUM_LISTS)
        return NULL;

    // Pop one block from the non-empty list.
    char *ptr = pop(alloc, j);

    // If we got a larger block than what we needed,
    // we need to split it in halfs until we got it
    // to the right size.
    // 
    // We are basically shaving off the last half of
    // the chunk multiple times, so the block's pointer
    // doesn't change.
    while (j > i) {
        j--;
        char *sibling = sibling_of(ptr, 1U << (j + MIN_BLOCK_LOG2));
        append(alloc, j, sibling);
    }

    set_allocated(alloc, ptr, len, true);
    return ptr;
}

void buddy_free(struct buddy_alloc *alloc,
                size_t len, void *ptr)
{
    if (ptr == NULL || len == 0)
        return;

    if (len > MAX_BLOCK_SIZE)
        return;

    len = normalize_len(len);

    if (!is_allocated(alloc, ptr, len))
        return;
    set_allocated(alloc, ptr, len, false);

    for (;;) {

        int i = list_index_for_size(len);

        if (len == MAX_BLOCK_SIZE || sibling_allocated_considering_splits(alloc, ptr, len)) {
            append(alloc, i, ptr);
            break;
        }

        assert(alloc->lists[i]);
        remove_sibling_from_list(alloc, i, ptr);

        ptr = parent_of(ptr, len);
        len <<= 1;
    }
}

bool buddy_owned(struct buddy_alloc *alloc, void *ptr)
{
    return (uintptr_t) alloc->base <= (uintptr_t) ptr
        && (uintptr_t) alloc->base + alloc->size > (uintptr_t) ptr;
}

bool buddy_allocated(struct buddy_alloc *alloc, void *ptr, size_t len)
{
    return buddy_owned(alloc, ptr) && is_allocated(alloc, ptr, len);
}