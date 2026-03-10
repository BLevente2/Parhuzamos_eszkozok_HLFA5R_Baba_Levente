ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
.SHELLFLAGS := /C
MKDIR_BUILD := if not exist build mkdir build
MKDIR_OBJ := if not exist build\obj mkdir build\obj
MKDIR_BIN := if not exist build\bin mkdir build\bin
MKDIR_LIB := if not exist build\lib mkdir build\lib
RM_F := del /Q
RMDIR := rmdir /S /Q
SHARED_EXT := .dll
else
MKDIR_BUILD := mkdir -p build
MKDIR_OBJ := mkdir -p build/obj
MKDIR_BIN := mkdir -p build/bin
MKDIR_LIB := mkdir -p build/lib
RM_F := rm -f
RMDIR := rm -rf
SHARED_EXT := .so
endif

ifeq ($(origin CC),default)
CC := gcc
endif
AR ?= ar

OPENCL_LIBS ?= -lOpenCL
OPENCL_CFLAGS ?=

ifeq ($(OS),Windows_NT)
PIC :=
else
PIC := -fPIC
endif

CFLAGS := -std=c99 -O2 -Wall -Wextra -Iinclude $(OPENCL_CFLAGS) -DKERNEL_LOADER_BUILD_DLL $(PIC)
LDFLAGS :=

SRC := src/kernel_loader.c
OBJ := build/obj/kernel_loader.o

LIB_STATIC := build/lib/libkernel_loader.a

ifeq ($(OS),Windows_NT)
SHARED_LIB := build/bin/kernel_loader$(SHARED_EXT)
IMPORT_LIB := build/lib/libkernel_loader.dll.a
else
SHARED_LIB := build/bin/libkernel_loader$(SHARED_EXT)
IMPORT_LIB :=
endif

.PHONY: all shared lib clean

all: lib shared

build_dirs:
	$(MKDIR_BUILD)
	$(MKDIR_OBJ)
	$(MKDIR_BIN)
	$(MKDIR_LIB)

build/obj/%.o: src/%.c build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

lib: $(LIB_STATIC)

$(LIB_STATIC): build_dirs $(OBJ)
	$(AR) rcs $(LIB_STATIC) $(OBJ)

shared: $(SHARED_LIB)

ifeq ($(OS),Windows_NT)
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) -Wl,--out-implib,$(IMPORT_LIB) -Wl,--export-all-symbols $(LDFLAGS) $(OPENCL_LIBS)
else
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) $(LDFLAGS) $(OPENCL_LIBS)
endif

clean:
ifeq ($(OS),Windows_NT)
	-$(RM_F) build\obj\*.o 2>nul
	-$(RM_F) build\bin\*.dll 2>nul
	-$(RM_F) build\lib\*.a 2>nul
	-$(RMDIR) build 2>nul
else
	-$(RM_F) build/obj/*.o
	-$(RM_F) build/bin/*
	-$(RM_F) build/lib/*.a
	-$(RMDIR) build
endif
