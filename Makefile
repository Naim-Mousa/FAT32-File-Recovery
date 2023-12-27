CC=gcc
CFLAGS=-g 
LDFLAGS = -lcrypto

.PHONY: all
all: nyufile

nyufile: nyufile.o

nyufile.o: nyufile.c

.PHONY: clean
clean:
	rm -f *.o nyufile