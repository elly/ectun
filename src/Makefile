CFLAGS := -Wall -Wextra -g -fPIC -I../include
PREFIX ?= /usr/local

libectun.so : crypto.o ectun.o
	$(CC) $(CFLAGS) -shared -o $@ $^ -lpolarssl

test : test.o crypto.o ectun.o
	$(CC) $(CFLAGS) -o $@ $^ -lpolarssl

install : libectun.so
	install -d $(PREFIX)/include/ectun $(PREFIX)/lib
	install -m 644 crypto.h ectun.h $(PREFIX)/include/ectun
	install -m 755 libectun.so $(PREFIX)/lib

clean :
	$(RM) *.o test
