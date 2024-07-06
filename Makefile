CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Os
LDIR = -L../ptrace_do
IDIR = -I../ptrace_do
LIBS = -lptrace_do

OBJS = add_shellcode.o sig_string_to_int.o string_to_vector.o

all: sigsleeper

sigsleeper: sigsleeper.c sigsleeper.h shellcode-snippets.h $(OBJS)
	$(CC) $(CFLAGS) $(IDIR) $(LDIR) $(OBJS) -o sigsleeper sigsleeper.c $(LIBS)

add_shellcode: add_shellcode.c
	$(CC) $(CFLAGS) -c -o add_shellcode.o add_shellcode.c

sig_string_to_int: sig_string_to_int.c
	$(CC) $(CFLAGS) -c -o sig_string_to_int.o sig_string_to_int.c

string_to_vector: string_to_vector.c
	$(CC) $(CFLAGS) -c -o string_to_vector.o string_to_vector.c

clean: 
	rm -f sigsleeper $(OBJS)
