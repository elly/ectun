CFLAGS := -Wall -Wextra -g

test : test.o crypto.o ectun.o
	$(CC) $(CFLAGS) -o $@ $^ -lpolarssl

clean :
	$(RM) *.o test
