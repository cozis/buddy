
all:
	gcc test.c buddy.c -o test -Wall -Wextra -ggdb #-fsanitize=address,undefined