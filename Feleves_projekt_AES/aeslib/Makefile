ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
.SHELLFLAGS := /C
MKDIR_BUILD := if not exist build mkdir build
MKDIR_OBJ := if not exist build\obj mkdir build\obj
MKDIR_BIN := if not exist build\bin mkdir build\bin
MKDIR_LIB := if not exist build\lib mkdir build\lib
RM_F := del /Q
RMDIR := rmdir /S /Q
EXE := .exe
SHARED_EXT := .dll
else
MKDIR_BUILD := mkdir -p build
MKDIR_OBJ := mkdir -p build/obj
MKDIR_BIN := mkdir -p build/bin
MKDIR_LIB := mkdir -p build/lib
RM_F := rm -f
RMDIR := rm -rf
EXE :=
SHARED_EXT := .so
endif

CC := gcc
AR := ar

PROF ?= 0
GPROF ?= 0
FAST ?= 0

CFLAGS_BASE := -std=c99 -O2 -Wall -Wextra -Iinclude

ifeq ($(FAST),1)
CFLAGS_BASE := -std=c99 -O3 -march=native -fomit-frame-pointer -funroll-loops -Wall -Wextra -Iinclude
endif
LDFLAGS :=

ifeq ($(PROF),1)
CFLAGS_BASE += -DCRYPTO_PROFILE
endif

ifeq ($(GPROF),1)
CFLAGS_BASE += -pg
LDFLAGS += -pg
endif

ifeq ($(OS),Windows_NT)
PIC :=
else
PIC := -fPIC
endif

CFLAGS := $(CFLAGS_BASE) $(PIC)

SRC := src/aes.c src/aes_ctr.c src/aes_gcm.c src/cbc.c src/crypto_gf128.c src/crypto_padding.c src/crypto_timer.c src/crypto_profile.c src/crypto_ffi.c
OBJ := build/obj/aes.o build/obj/aes_ctr.o build/obj/aes_gcm.o build/obj/cbc.o build/obj/crypto_gf128.o build/obj/crypto_padding.o build/obj/crypto_timer.o build/obj/crypto_profile.o build/obj/crypto_ffi.o

LIB_STATIC := build/lib/libcrypto_aes.a

TEST_SRC := tests/test_aes.c
TEST_OBJ := build/obj/test_aes.o
TEST_BIN := build/bin/test_aes$(EXE)

BENCH_SRC := tests/bench_aes.c
BENCH_OBJ := build/obj/bench_aes.o
BENCH_BIN := build/bin/bench_aes$(EXE)

ifeq ($(OS),Windows_NT)
SHARED_LIB := build/bin/crypto_aes$(SHARED_EXT)
IMPORT_LIB := build/lib/libcrypto_aes.dll.a
else
SHARED_LIB := build/bin/libcrypto_aes$(SHARED_EXT)
IMPORT_LIB :=
endif

.PHONY: all lib shared test bench clean

all: lib shared test bench

build_dirs:
	$(MKDIR_BUILD)
	$(MKDIR_OBJ)
	$(MKDIR_BIN)
	$(MKDIR_LIB)

lib: $(LIB_STATIC)

shared: $(SHARED_LIB)

test: $(TEST_BIN)

bench: $(BENCH_BIN)

$(LIB_STATIC): build_dirs $(OBJ)
	$(AR) rcs $(LIB_STATIC) $(OBJ)

build/obj/%.o: src/%.c build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_OBJ): $(TEST_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(TEST_SRC) -o $(TEST_OBJ)

$(TEST_BIN): build_dirs $(LIB_STATIC) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) $(LIB_STATIC) -o $(TEST_BIN) $(LDFLAGS)

$(BENCH_OBJ): $(BENCH_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(BENCH_SRC) -o $(BENCH_OBJ)

$(BENCH_BIN): build_dirs $(LIB_STATIC) $(BENCH_OBJ)
	$(CC) $(CFLAGS) $(BENCH_OBJ) $(LIB_STATIC) -o $(BENCH_BIN) $(LDFLAGS)

ifeq ($(OS),Windows_NT)
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) -Wl,--out-implib,$(IMPORT_LIB) -Wl,--export-all-symbols $(LDFLAGS)
else
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) $(LDFLAGS)
endif

clean:
ifeq ($(OS),Windows_NT)
	-$(RM_F) build\obj\*.o 2>nul
	-$(RM_F) build\bin\*$(EXE) 2>nul
	-$(RM_F) build\bin\*.dll 2>nul
	-$(RM_F) build\lib\*.a 2>nul
	-$(RMDIR) build 2>nul
else
	-$(RM_F) build/obj/*.o
	-$(RM_F) build/bin/*
	-$(RM_F) build/lib/*.a
	-$(RM_F) build/bin/*.so
	-$(RMDIR) build
endif
