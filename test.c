#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include "buddy.h"

#define NUM_PAGES 32
#define PAGE_SIZE  (1 << 12)
#define MAX_ALLOCS (1 << 14)

struct alloc_info {
    uintptr_t ptr;
    uintptr_t len;
};

static bool contains_ptr(struct alloc_info *array, int count, void *ptr)
{
    uintptr_t x = (uintptr_t) ptr;

    for (int i = 0; i < count; i++) {
        uintptr_t head = array[i].ptr;
        uintptr_t tail = array[i].len + head;
        if (x >= head && x < tail)
            return true;
    }
    return false;
}

int main(void)
{
    _Alignas(PAGE_SIZE) char mem[NUM_PAGES * PAGE_SIZE];
    struct buddy_alloc alloc;
    uint32_t alloc_bits[NUM_PAGES];
    init_buddy_alloc(&alloc, mem, sizeof(mem), alloc_bits, NUM_PAGES);

    struct alloc_info current_allocs[MAX_ALLOCS];
    int num_current_allocs = 0;
 
    for (;;) {

        if (num_current_allocs > 0) {
            int i = rand() % num_current_allocs;
            struct alloc_info deallocating = current_allocs[i];
            current_allocs[i] = current_allocs[--num_current_allocs];
            buddy_free(&alloc, (void*) deallocating.ptr, deallocating.len);
        }

        size_t len = 1 + (rand() % PAGE_SIZE);
        assert(len > 0 && len <= PAGE_SIZE);

        void *ptr = buddy_malloc(&alloc, len);
        if (ptr == NULL)
            continue;

        /*
         * Check that it isn't currently allocated
         */
        assert(contains_ptr(current_allocs, num_current_allocs, ptr) == false);
        current_allocs[num_current_allocs++] = (struct alloc_info) {.ptr=(uintptr_t)ptr, .len=len};
    }

    free_buddy_alloc(&alloc);
    return 0;
}