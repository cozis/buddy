#include <assert.h>
#include <stdbool.h>
#include "buddy.h"

enum {
    INDEX_256B,
    INDEX_512B,
    INDEX_1K,
    INDEX_2K,
    INDEX_4K,
};

struct page {
    struct page *next;
};

void init_buddy_alloc(struct buddy_alloc *alloc,
                      char *base, size_t size,
                      uint32_t *bitsets,
                      int num_bitsets)
{
    size_t page_size = 1 << 12;

    /*
     * Ad some padding to the start of the
     * memory pool to align at a page boundary.
     */
    size_t pad = -(uintptr_t) base & (page_size - 1);

    if (pad > size) {
        /*
         * Pool doesn't have a whole page
         */
        alloc->base = NULL;
        alloc->lists[INDEX_256B] = NULL;
        alloc->lists[INDEX_512B] = NULL;
        alloc->lists[INDEX_1K] = NULL;
        alloc->lists[INDEX_2K] = NULL;
        alloc->lists[INDEX_4K] = NULL;
        alloc->bitsets = NULL;
        alloc->num_bitsets = 0;
        return;
    }

    base += pad;
    size -= pad;

    /*
     * Make the size a multiple of 4K
     */
    size_t rem = size % page_size;

    size -= rem;

    /*
     * Each page requires a bitset to keep track of its state
     */
    size_t max_bytes = (size_t) num_bitsets * page_size;
    if (size > max_bytes)
        size = max_bytes;

    /*
     * Make the linked list of pages
     */
    struct page *head;
    struct page **tail = &head;
    size_t num_pages = size / page_size;

    for (size_t i = 0; i < num_pages; i++) {
        struct page *p = (struct page*) (base + i * page_size);
        *tail = p;
        tail = &p->next;
    }
    *tail = NULL;

    alloc->base = base;
    alloc->lists[INDEX_256B] = NULL;
    alloc->lists[INDEX_512B] = NULL;
    alloc->lists[INDEX_1K] = NULL;
    alloc->lists[INDEX_2K] = NULL;
    alloc->lists[INDEX_4K] = head;
    alloc->bitsets = bitsets;
    alloc->num_bitsets = num_bitsets;

    for (int i = 0; i < num_bitsets; i++)
        alloc->bitsets[i] = 0;
}

void free_buddy_alloc(struct buddy_alloc *alloc)
{
    (void) alloc;
}

static bool is_pow2(size_t n)
{
    return (n & (n-1)) == 0;
}

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
 * Returns the index from the right of the
 * first set bit or -1 otherwise.
 */
static int first_set_bit(size_t bits)
{
    // First check that at least one bit is set
    if (bits == 0) return -1;
    
    size_t bits_no_rightmost = bits & (bits - 1);
    size_t bits_only_rightmost = bits - bits_no_rightmost;

    int index = 0;
    size_t temp;

    if (sizeof(size_t) > 4) {
        // The index of the rightmost bit is the log2
        temp = bits_only_rightmost >> 32;
        if (temp) {
            // Bit is in the upper 32 bits
            index += 32;
            bits_only_rightmost = temp;
        }
    }

    temp = bits_only_rightmost >> 16;
    if (temp) {
        index += 16;
        bits_only_rightmost = temp;
    }

    temp = bits_only_rightmost >> 8;
    if (temp) {
        index += 8;
        bits_only_rightmost = temp;
    }

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

    index += table[bits_only_rightmost];
    
    return index;
}

void *malloc_internal(struct buddy_alloc *alloc, size_t len)
{
    size_t page_size = 1 << 12;

    if (len > page_size)
        return NULL;

    if (len == 0)
        return NULL;

    if (len < 256)
        len = 256;
    else {
        len = round_pow2(len);
        if (len > page_size)
            return NULL;
    }

    int i = first_set_bit(len);

    assert(first_set_bit(256) == 8);
    int list_idx = i - 8;

    struct page *p = alloc->lists[list_idx];

    /*
     * If there isn't a page of the appropriate size,
     * allocate a block twice as big, allocate one half
     * and put the other one in a list.
     */
    if (p == NULL) {

        char *ptr = malloc_internal(alloc, len << 1);
        if (ptr == NULL)
            return NULL;

        p = (struct page*) ptr;
        p->next = NULL;

        struct page *p2;
        p2 = (struct page*) (ptr + len);
        p2->next = NULL;
        alloc->lists[list_idx] = p2;

    } else {
        alloc->lists[list_idx] = p->next;
    }

    return p;
}

static void *get_sibling(void *ptr, size_t len)
{
    size_t double_len = len << 1;

    if ((uintptr_t) ptr & (double_len - 1))
        return ptr + len;
    else
        return ptr - len;
}

static void *parent_chunk(void *ptr, size_t len)
{
    void *sib = get_sibling(ptr, len);
    if ((uintptr_t) sib < (uintptr_t) ptr)
        return sib;
    else
        return ptr;
}

static void
append_to_list(struct buddy_alloc *alloc,
               void *ptr, size_t len)
{
    assert(is_pow2(len));
    assert(len >= 256);

    int list_idx = first_set_bit(len) - 8;

    assert(list_idx >= 0 && list_idx <= INDEX_4K);

    struct page *p = ptr;

    p->next = alloc->lists[list_idx];
    alloc->lists[list_idx] = p;
}

void free_internal(struct buddy_alloc *alloc,
                   void *ptr, size_t len)
{
    if (len < 256)
        len = 256;
    else {
        if (len > 4096)
            return;
        len = round_pow2(len);
    }

    size_t page_size = 1 << 12;
    assert(len > 0 && len <= page_size);

    if (len == page_size) {
        /*
         * Deallocation is easy, just push into
         * the last list.
         */
        append_to_list(alloc, ptr, len);
        return;
    }

    /*
     * Before placing this chunk in the free list
     * look for its sibling and pop it.
     * 
     * If the chunk is aligned to double its size,
     * its sibling is the one after it, else it's
     * the one before it.
     */
    bool found = false;
    char *sibling = get_sibling(ptr, len);
    {
        int list_idx = first_set_bit(len) - 8;
        struct page  *curs = (struct page*) alloc->lists[list_idx];
        struct page **prev = (struct page**) &alloc->lists[list_idx];

        while (curs) {
            if (curs == (struct page*) sibling) {
                *prev = curs->next;
                found = true;
                break;
            }
            prev = &curs->next;
            curs =  curs->next;
        }
    }

    if (found == false) {
        /*
         * No sybling so just push this chunk in
         * the list.
         */
        append_to_list(alloc, ptr, len);
    } else {
        /*
         * Deallocate the larger chunk
         */
        struct page *p = parent_chunk(ptr, len);
        free_internal(alloc, p, len << 1);
    }
}

uint32_t get_chunk_mask(void *ptr, size_t len)
{
    assert(len > 0);

    len = round_pow2(len);

    size_t page_size = 1 << 12;

    uintptr_t x = (uintptr_t) ptr;

    /*
     * Get the bit associated to the chunk
     *
     * The first bit refers to the entire page,
     * the following 2 bits refer to its halfs,
     * then the following 4 the halfs of the
     * halfs and so on.
     */

    int len_log2 = first_set_bit(len);
    assert(len_log2 <= 12);

    // Pointer relative to its page 
    size_t reloff = x & (page_size - 1);

    size_t chidx = reloff / len;

    size_t sh = 12 - len_log2 + chidx;

    uint32_t mask = 1;
    mask <<= sh;

    /*
     * Each bit is associated to a chunk. Chunk bits are
     * grouped by their size. The bit index of the first
     * chunk if its length can be calculated as:
     * 
     *     12 - log2(len)
     *
     * From there, the bit index is displaced as the chunk
     * in the page:
     * 
     *     12 - log2(len) + (ptr - page_ptr) / len
     * 
     * For convenience, here's the list of the bits:
     * 
     *      1 - 4K - 2^12 -> 2^0
     *      2 - 2K - 2^11 -> 2^1
     *      3 - 2K
     *      4 - 1K - 2^10 -> 2^2
     *      5 - 1K
     *      6 - 1K
     *      7 - 1K
     *      8 - 512b - 2^9 -> 2^3
     *      9 - 512b
     *     10 - 512b
     *     11 - 512b
     *     12 - 512b
     *     13 - 512b
     *     14 - 512b
     *     15 - 512b
     *     16 - 256b - 2^8 -> 2^4
     *     17 - 256b
     *     18 - 256b
     *     19 - 256b
     *     20 - 256b
     *     21 - 256b
     *     22 - 256b
     *     23 - 256b
     *     24 - 256b
     *     25 - 256b
     *     26 - 256b
     *     27 - 256b
     *     28 - 256b
     *     29 - 256b
     *     30 - 256b
     *     31 - 256b
     */

    return mask;
}

void set_chunk_state(struct buddy_alloc *alloc,
                     void *ptr, size_t len, bool used)
{
    len = round_pow2(len);

    size_t page_size = 1 << 12;

    uintptr_t x = (uintptr_t) ptr;

    int page_index = (x - (uintptr_t) alloc->base) / page_size;

    uint32_t mask = get_chunk_mask(ptr, len);

    if (used)
        alloc->bitsets[page_index] |= mask;
    else
        alloc->bitsets[page_index] &= ~mask;
}

bool get_chunk_state(struct buddy_alloc *alloc,
                     void *ptr, size_t len)
{
    size_t page_size = 1 << 12;

    uintptr_t x = (uintptr_t) ptr;

    int page_index = (x - (uintptr_t) alloc->base) / page_size;

    uint32_t mask = get_chunk_mask(ptr, len);

    return (alloc->bitsets[page_index] & mask) == mask;
}

void *buddy_malloc(struct buddy_alloc *alloc, size_t len)
{
    void *ptr = malloc_internal(alloc, len);
    if (ptr)
        set_chunk_state(alloc, ptr, len, 1);
    return ptr;
}

void buddy_free(struct buddy_alloc *alloc,
                void *ptr, size_t len)
{
    if (get_chunk_state(alloc, ptr, len)) {
        set_chunk_state(alloc, ptr, len, 0);
        free_internal(alloc, ptr, len);
    }
}

bool buddy_allocated(struct buddy_alloc *alloc,
                     void *ptr, size_t len)
{
    return get_chunk_state(alloc, ptr, len);
}
