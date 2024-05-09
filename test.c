#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include "buddy.h"

#define NUM_PAGES  2
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
    
    struct page_info info[NUM_PAGES];
    struct buddy_alloc alloc = buddy_startup(mem, sizeof(mem), info, NUM_PAGES);

    struct alloc_info current_allocs[MAX_ALLOCS];
    int num_current_allocs = 0;
 
    int failed = 0;
    for (;;) {

        if (failed == 10 || num_current_allocs == MAX_ALLOCS) {
            failed = 0;
            while (1 + rand() % 10 < 6 && num_current_allocs > 0) {
                int i = rand() % num_current_allocs;
                struct alloc_info deallocating = current_allocs[i];
                current_allocs[i] = current_allocs[--num_current_allocs];
                fprintf(stderr, "buddy_free(%d, %d)\n", (int) deallocating.len, (int) ((uintptr_t) deallocating.ptr - (uintptr_t) alloc.base));
                buddy_free(&alloc, deallocating.len, (void*) deallocating.ptr);
            }
        }

        size_t len = 1 + (rand() % PAGE_SIZE);
        assert(len > 0 && len <= PAGE_SIZE);

        void *ptr = buddy_malloc(&alloc, len);

        if (ptr == NULL) {
            failed++;
            //fprintf(stderr, "buddy_malloc(%lu) = NULL\n", len);
        } else {
            //buddy_dump(&alloc, stderr);
            fprintf(stderr, "buddy_malloc(%d) = %d\n", (int) len, (int) ((uintptr_t) ptr - (uintptr_t) alloc.base));
        }

        if (ptr != NULL) {

            assert(contains_ptr(current_allocs, num_current_allocs, ptr) == false);
            current_allocs[num_current_allocs++] = (struct alloc_info) {.ptr=(uintptr_t)ptr, .len=len};
/*
            fprintf(stderr, "Allocations:\n");
            for (int i = 0; i < num_current_allocs; i++) {
                fprintf(stderr, "  len: %-4lu | ptr: %lu\n", current_allocs[i].len, (uintptr_t) current_allocs[i].ptr - (uintptr_t) alloc.base);
            }
*/
        }
    }

    buddy_cleanup(&alloc);
    return 0;
}