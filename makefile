CC=gcc
CFLAGS=-O2 -Wall
CLANG=clang
CLANGFLAGS=-O2 -target bpf -c

all: tx_program xdp_tx_kern.o

tx_program: main.c xdp_tx_kern.o
	$(CC) $(CFLAGS) -o tx_program main.c -lpthread -lbpf

xdp_tx_kern.o: xdp_tx_kern.c
	$(CLANG) $(CLANGFLAGS) xdp_tx_kern.c -o xdp_tx_kern.o

clean:
	rm -f tx_program xdp_tx_kern.o
