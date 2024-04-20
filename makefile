
all:
	gcc test.c  buddy.c -o test  -Wall -Wextra -ggdb #-fsanitize=address,undefined
	gcc test2.c buddy.c -o test2 -Wall -Wextra -ggdb