# Compiler and flags
CC       := gcc
CFLAGS   := -Wall -Wextra -O2 -pthread -Iinclude

# Directories
SRCDIR   := src
INCDIR   := include

# Target executable
TARGET   := filehasher

# Source and object files
SRCS     := $(wildcard $(SRCDIR)/*.c)
OBJS     := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

# Compile .c -> .o
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
