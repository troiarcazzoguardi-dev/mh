CC = gcc
CFLAGS = -O2 -Wall
LDFLAGS = -lpthread -lbpf

# Solo se vuoi compilare BPF/XDP
CLANG = clang
BPF_CFLAGS = -O2 -g -target bpf \
	-I/lib/modules/$(shell uname -r)/build/include \
	-I/usr/include

SRC_MAIN = main.c
SRC_BPF  = xdp_tx_kern.c
OBJ_BPF  = xdp_tx_kern.o
TARGET   = tx_program

.PHONY: all clean

all: $(TARGET)

# Compila solo il main.c (sempre funzionante)
$(TARGET): $(SRC_MAIN)
	$(CC) $(CFLAGS) $(SRC_MAIN) -o $(TARGET) $(LDFLAGS)

# Compila BPF/XDP solo se vuoi usare XDP
$(OBJ_BPF): $(SRC_BPF)
	$(CLANG) $(BPF_CFLAGS) -c $(SRC_BPF) -o $(OBJ_BPF)

clean:
	rm -f $(TARGET) $(OBJ_BPF)