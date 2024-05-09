#include <stdio.h>
#include "buddy.h"

#define NUM_PAGES 16

#define MIN_ALLOC_SIZE (1U << BUDDY_ALLOC_MIN_BLOCK_LOG2)
#define PAGE_SIZE (1U << BUDDY_ALLOC_MAX_BLOCK_LOG2)
#define POOL_SIZE (NUM_PAGES * PAGE_SIZE)
#define MAX_ALLOCS (POOL_SIZE / MIN_ALLOC_SIZE)

int main(void)
{
    _Alignas(PAGE_SIZE) char mem[POOL_SIZE];
    struct page_info info[NUM_PAGES];
    struct buddy_alloc alloc = buddy_startup(mem, POOL_SIZE, info, NUM_PAGES);

    void *allocs[MAX_ALLOCS];

    size_t performed = 0;
    for (size_t i = 0; i < MAX_ALLOCS; i++) {
        void *ptr = buddy_malloc(&alloc, MIN_ALLOC_SIZE);
        if (ptr == NULL)
            break;
        
        performed++;

        allocs[i] = ptr;

        *(size_t*) ptr = i;
    }

    if (performed == MAX_ALLOCS) {

        for (size_t i = 0; i < MAX_ALLOCS; i++) {
            if (*(size_t*) allocs[i] != i)
                fprintf(stderr, "%p allocated twice!\n", allocs[i]);
        }

        for (size_t i = 0; i < MAX_ALLOCS; i++) {
            buddy_free(&alloc, MIN_ALLOC_SIZE, allocs[MAX_ALLOCS-i-1]);
        }

        performed = 0;
        for (size_t i = 0; i < MAX_ALLOCS; i++) {
            void *ptr = buddy_malloc(&alloc, MIN_ALLOC_SIZE);
            performed++;

            allocs[i] = ptr;

            *(size_t*) ptr = i + MAX_ALLOCS;
        }

        for (size_t i = 0; i < MAX_ALLOCS; i++) {
            if (*(size_t*) allocs[i] != MAX_ALLOCS + i)
                fprintf(stderr, "%p reallocation error!\n", allocs[i]);
        }
    }

    fprintf(stderr, "performed=%d, expected=%d\n", (int) performed, (int) MAX_ALLOCS);

    buddy_cleanup(&alloc);
    return 0;
}
