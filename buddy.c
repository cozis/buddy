/*
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
 */

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#define BUDDY_DEBUG
#ifdef BUDDY_DEBUG
#include <stdio.h>
#endif

#include "buddy.h"

#define MAX_BLOCK_LOG2 BUDDY_ALLOC_MAX_BLOCK_LOG2
#define MIN_BLOCK_LOG2 BUDDY_ALLOC_MIN_BLOCK_LOG2
#define MAX_BLOCK_SIZE (1 << MAX_BLOCK_LOG2)
#define MIN_BLOCK_SIZE (1 << MIN_BLOCK_LOG2)
#define MAX_BLOCK_ALIGN_MASK (MAX_BLOCK_SIZE - 1)

struct page {
    struct page *next;
};

static struct page*
page_index_to_ptr(char *base, int i)
{
    return (struct page*) (base + (i << MAX_BLOCK_LOG2));
}

static struct buddy_alloc startup_empty()
{
    struct buddy_alloc alloc;
    alloc.base = NULL;
    alloc.info = NULL;
    alloc.num_info = 0;
    for (int i = 0; i < BUDDY_ALLOC_NUM_LISTS; i++)
        alloc.lists[i] = NULL;
    return alloc;
}

struct buddy_alloc buddy_startup(char *base, size_t size,
                                 struct page_info *info,
                                 int num_info)
{
    if (base == NULL || info == NULL)
        return startup_empty();

    /*
     * Ad some padding to the start of the
     * memory pool to align at a page boundary.
     */
    size_t pad = -(uintptr_t) base & MAX_BLOCK_ALIGN_MASK;

    if (pad > size) {
        /*
         * Pool doesn't even have a page
         */
        return startup_empty();
    }

    base += pad;
    size -= pad;

    /*
     * Make the size a multiple of 4K
     */
    size_t rem = size & MAX_BLOCK_ALIGN_MASK;
    size -= rem;

    /*
     * Each page requires a bitset to keep track of its state
     */
    size_t max_bytes = (size_t) num_info << MAX_BLOCK_LOG2;
    if (size > max_bytes)
        size = max_bytes;

    /*
     * Make the linked list of pages
     */
    struct page *head = NULL;
    struct page **tail = &head;
    int num_pages = size >> MAX_BLOCK_LOG2;
    for (int i = 0; i < num_pages; i++) {
        struct page *p = page_index_to_ptr(base, i);
        *tail = p;
        tail = &p->next;
    }
    *tail = NULL;

    assert(info);
    memset(info, 0, num_info * sizeof(struct page_info));

    struct buddy_alloc alloc;
    alloc.base = base,
    alloc.info = info;
    alloc.num_info = num_info;
    for (int i = 0; i < BUDDY_ALLOC_NUM_LISTS-1; i++)
        alloc.lists[i] = NULL;
    alloc.lists[BUDDY_ALLOC_NUM_LISTS-1] = head;

    return alloc;
}

void buddy_cleanup(struct buddy_alloc *alloc)
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

static int first_set_8(uint8_t x)
{
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
    return table[x];
}

// Returns the index from the right of the first set bit or -1 otherwise.
static int first_set(size_t x)
{
    size_t y;
    size_t z;
    size_t t;
    int i;

    // First check that at least one bit is set
    if (x == 0) return -1;

    y = x & (x - 1);
    z = x - y;
    i = 0;

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

    i += first_set_8(z);

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

static void set_allocated(struct buddy_alloc *alloc,
                          void *ptr, size_t len, bool value)
{
    assert(is_pow2(len));

    size_t i = page_index(alloc, ptr);
    size_t j = block_info_index(ptr, len);

    int bits_per_word_log2 = 5;
    int bits_per_word = 1 << bits_per_word_log2;

    int u = j >> bits_per_word_log2;
    int v = j & (bits_per_word - 1);

    uint32_t mask = 1U << v;
    if (value)
        alloc->info[i].bits[u] |= mask;
    else
        alloc->info[i].bits[u] &= ~mask;
}

static bool
is_allocated_considering_splits(struct buddy_alloc *alloc,
                                void *ptr, size_t len)
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
    return first_set(len) - MIN_BLOCK_LOG2;
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
    struct page *sibling = (struct page*) sibling_of(ptr, len);
    struct page *curs = (struct page*) alloc->lists[i];
    struct page **prev = (struct page**) &alloc->lists[i];
    while (curs != (struct page*) sibling) {
        assert(curs);
        prev = &curs->next;
        curs =  curs->next;
        assert(curs);
    }
    assert(sibling == curs);
    *prev = sibling->next;
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
    
    struct page *pag = ptr;

    pag->next = alloc->lists[i];
    alloc->lists[i] = pag;
}

static char *pop(struct buddy_alloc *alloc, int i)
{
    assert(i >= 0 && i < BUDDY_ALLOC_NUM_LISTS);
    
    char *ptr = alloc->lists[i];
    assert(ptr);

    alloc->lists[i] = ((struct page*) ptr)->next;
    return ptr;
}

void *buddy_malloc(struct buddy_alloc *alloc, size_t len)
{    
    if (len == 0 || len > MAX_BLOCK_SIZE) 
        return NULL;
    if (alloc->base == NULL)
        return NULL;
    len = normalize_len(len);

    // Index of the list of blocks with size "len"
    int i = list_index_for_size(len);

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
    if (ptr == NULL || len == 0) return;
    if (len > MAX_BLOCK_SIZE) return;
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

/*
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static const char *block_size_label(size_t len)
{
    const char *label = "???";
    switch (len) {
        case 1<<12: label = "4K"; break;
        case 1<<11: label = "2K"; break;
        case 1<<10: label = "1K"; break;
        case 1<<9 : label = "512B"; break;
        case 1<<8 : label = "256B"; break;
    }
    return label;
}

void print_lists(struct buddy_alloc *alloc)
{
    for (int i = MIN_BLOCK_LOG2; i <= MAX_BLOCK_LOG2; i++) {
        fprintf(stderr, "%s = {", block_size_label(1U<<i));
        struct page *p = alloc->lists[i - MIN_BLOCK_LOG2];
        while (p) {
            assert((uintptr_t) p >= (uintptr_t) alloc->base);
            fprintf(stderr, "%lu", (uintptr_t) p - (uintptr_t) alloc->base);
            p = p->next;
            if (p)
                fprintf(stderr, ", ");
        }
        fprintf(stderr, "}\n");
    }
}

void buddy_dump(struct buddy_alloc *alloc, FILE *out)
{
    fprintf(out, "\n");

    for (int i = 0; i < alloc->num_info; i++) {
        for (int j = 0; j < 32; j++) {
            if (alloc->info[i].bits[0] & (1U << j))
                fprintf(stderr, "1");
            else
                fprintf(stderr, "0");
        }
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");

    for (int i = 0; i < alloc->num_info; i++) {
        char *page = alloc->base + i * MAX_BLOCK_SIZE;
        for (int j = MAX_BLOCK_LOG2; j >= MIN_BLOCK_LOG2; j--) {

            size_t len = 1U << j;

            const char *label = block_size_label(len);

            for (size_t k = 0; k < MAX_BLOCK_SIZE / len; k++) {

                char *ptr = page + k * len;

                fprintf(out, "%-4lX ", (uintptr_t) ptr - (uintptr_t) alloc->base);

                for (int q = 0; q < MAX_BLOCK_LOG2 - j; q++)
                    fprintf(out, "  ");

                if (is_allocated(alloc, ptr, len))
                    fprintf(out, ANSI_COLOR_GREEN "%s - allocated\n" ANSI_COLOR_RESET, label);
                else
                    fprintf(out, "%s - free\n", label);
            }
        }
    }
}
*/