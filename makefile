
all:
	gcc test.c  buddy.c -o test  -Wall -Wextra -ggdb
	gcc test2.c buddy.c -o test2 -Wall -Wextra -ggdb
	gcc example.c buddy.c -o example -Wall -Wextra -ggdb
