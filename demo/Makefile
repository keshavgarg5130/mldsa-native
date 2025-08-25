# Compiler
CC = gcc

# Include directory for ML-DSA headers
INCLUDES = -I../mldsa

# Source files
SRCS = demo.c $(shell find ../mldsa -name "*.c" ! -name "randombytes.c")

# Output binary
OUT = demo

# Mode define
CFLAGS = -DMLDSA_MODE=3

all:
	$(CC) $(CFLAGS) $(SRCS) $(INCLUDES) -o $(OUT)

clean:
	rm -f $(OUT)
