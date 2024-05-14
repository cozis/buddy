# A Buddy Allocator
This is a general purpose allocator designed for memory-constrained environments. It uses the Buddy System allocation scheme. Only allocations with a size that is a power of 2 are supported. Any size other that's not a power of 2 will be rounded up.

Here's an example:

```c
#include <stdio.h>
#include <string.h>
#include "buddy.h"

int main(void)
{
    // This is the memory we will allocate from
    char memory[1 << 20];

    struct buddy *alloc = buddy_startup(memory, sizeof(memory));

    // Allocate some memory (NULL is returned on failure)
    char *str1 = buddy_malloc(alloc, 32);
    char *str2 = buddy_malloc(alloc, 32);

    strncpy(str1, "Hello", 32);
    strncpy(str2, "world", 32);

    printf("%s, %s!\n", str1, str2);

    buddy_free(alloc, 32, str1);
    buddy_free(alloc, 32, str2);

    buddy_free(alloc, 32, str2); // Double frees are caught!

    return 0;
}
```
