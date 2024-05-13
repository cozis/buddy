#pragma once

#include <cstddef>
#include <stdexcept>

#include "buddy.h"

class BuddyAllocator {
    private:
        struct buddy_alloc allocator;
        struct page_info info; // I didn't understand the point of the pages though
    public:
        BuddyAllocator(std::byte* memory, std::size_t size) {
            buddy_startup(reinterpret_cast<char*>(memory), size, &info, 1);
        }

        ~BuddyAllocator() {
            buddy_cleanup(&allocator);
        }

        std::byte* allocate(std::size_t size) {
            auto* ptr = reinterpret_cast<std::byte*>(buddy_malloc(&allocator, size));
            if (ptr == nullptr) {
                throw std::runtime_error("todo");
            }
            return ptr;
        }

        void free(std::size_t size, std::byte* ptr) {
            buddy_free(&allocator, size, ptr);
        }
};