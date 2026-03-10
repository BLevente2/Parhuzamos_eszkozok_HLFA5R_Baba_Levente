# Compiler and flags
CC        := gcc
CFLAGS    := -std=c11 -Wall -O2 -fopenmp -Iinclude
LDFLAGS   := -lcrypto

# Directories
SRC_DIR   := src
INCLUDE_DIR := include

# Source files and objects
SRCS      := $(wildcard $(SRC_DIR)/*.c)
OBJS      := $(SRCS:.c=.o)

# Final executable
TARGET    := app

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Generic rule for compiling .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)