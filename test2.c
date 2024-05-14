#include <stdlib.h>
#include "buddy.h"

int main(void)
{
    char mem[1<<20];
    for (int i = 0; i < 100; i++) {

        void  *base = mem;
        size_t size = sizeof(mem);

        size_t pad = rand() % size;
        base += pad;
        size -= pad;

        size_t len = rand() % (size+1);

        struct buddy *b = buddy_startup(base, len);
    }
    return 0;
}