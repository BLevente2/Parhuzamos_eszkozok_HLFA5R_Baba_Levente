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

ifeq ($(OS),Windows_NT)
COPY_KERNELS := if not exist build\bin\kernels mkdir build\bin\kernels
COPY_KERNELS += & copy /Y kernels\*.cl build\bin\kernels >nul
else
COPY_KERNELS := mkdir -p build/bin/kernels && cp -f kernels/*.cl build/bin/kernels/
endif

CC := gcc
AR := ar

PROF ?= 0
FAST ?= 0

OPENCL_LIBS ?= -lOpenCL
OPENCL_CFLAGS ?=

AESLIB_DIR := ../aeslib
KERNEL_LOADER_DIR := ../kernel_loader

CFLAGS_BASE := -std=c99 -O2 -Wall -Wextra -Iinclude -I$(AESLIB_DIR)/include -I$(KERNEL_LOADER_DIR)/include $(OPENCL_CFLAGS) -DCRYPTO_OPENCL_BUILD_DLL

ifeq ($(FAST),1)
CFLAGS_BASE := -std=c99 -O3 -march=native -fomit-frame-pointer -funroll-loops -Wall -Wextra -Iinclude -I$(AESLIB_DIR)/include -I$(KERNEL_LOADER_DIR)/include $(OPENCL_CFLAGS) -DCRYPTO_OPENCL_BUILD_DLL
endif

LDFLAGS :=

ifeq ($(PROF),1)
CFLAGS_BASE += -DCRYPTO_OCL_PROFILE
endif

ifeq ($(OS),Windows_NT)
PIC :=
else
PIC := -fPIC
endif

CFLAGS := $(CFLAGS_BASE) $(PIC)

ifeq ($(OS),Windows_NT)
DEPS_LD_DIRS := -L$(AESLIB_DIR)/build/lib -L$(KERNEL_LOADER_DIR)/build/lib
DEPS_LD_LIBS := -lcrypto_aes -lkernel_loader
AESLIB_DLL := ..\aeslib\build\bin\crypto_aes$(SHARED_EXT)
KERNEL_LOADER_DLL := ..\kernel_loader\build\bin\kernel_loader$(SHARED_EXT)
RPATH_LDFLAGS :=
else
DEPS_LD_DIRS := -L$(AESLIB_DIR)/build/bin -L$(KERNEL_LOADER_DIR)/build/bin
DEPS_LD_LIBS := -lcrypto_aes -lkernel_loader
AESLIB_DLL := $(AESLIB_DIR)/build/bin/libcrypto_aes$(SHARED_EXT)
KERNEL_LOADER_DLL := $(KERNEL_LOADER_DIR)/build/bin/libkernel_loader$(SHARED_EXT)
RPATH_LDFLAGS := -Wl,-rpath,'$$ORIGIN'
endif

DEPS_LDFLAGS := $(DEPS_LD_DIRS) $(DEPS_LD_LIBS) $(RPATH_LDFLAGS)

SRC := src/opencl_aes_ctr.c src/crypto_ffi_opencl.c src/crypto_ocl_profile.c
OBJ := build/obj/opencl_aes_ctr.o build/obj/crypto_ffi_opencl.o build/obj/crypto_ocl_profile.o

LIB_STATIC := build/lib/libcrypto_aes_opencl.a

TEST_SRC := tests/test_opencl_aes.c
TEST_OBJ := build/obj/test_opencl_aes.o
TEST_BIN := build/bin/test_opencl_aes$(EXE)

BENCH_SRC := tests/bench_opencl_aes.c
BENCH_OBJ := build/obj/bench_opencl_aes.o
BENCH_BIN := build/bin/bench_opencl_aes$(EXE)

PROFILE_SRC := tests/profile_opencl_aes.c
PROFILE_OBJ := build/obj/profile_opencl_aes.o
PROFILE_BIN := build/bin/profile_opencl_aes$(EXE)

ifeq ($(OS),Windows_NT)
SHARED_LIB := build/bin/crypto_aes_opencl$(SHARED_EXT)
IMPORT_LIB := build/lib/libcrypto_aes_opencl.dll.a
else
SHARED_LIB := build/bin/libcrypto_aes_opencl$(SHARED_EXT)
IMPORT_LIB :=
endif

.PHONY: all deps copy_deps lib shared test bench profile copy_kernels clean build_dirs

.NOTPARALLEL: all deps copy_deps lib shared test bench copy_kernels

ifeq ($(PROF),1)
PROFILE_TARGET := profile
else
PROFILE_TARGET :=
endif

all:
	$(MAKE) deps
	$(MAKE) lib
	$(MAKE) shared
	$(MAKE) test
	$(MAKE) bench
ifeq ($(PROF),1)
	$(MAKE) profile
endif
	$(MAKE) copy_kernels
	$(MAKE) copy_deps

deps:
	$(MAKE) -C $(AESLIB_DIR) shared
	$(MAKE) -C $(KERNEL_LOADER_DIR) all

copy_deps: deps build_dirs

ifeq ($(OS),Windows_NT)
	if not exist build\bin mkdir build\bin
	if not exist $(AESLIB_DLL) (echo Missing dependency: $(AESLIB_DLL) & exit /b 1)
	if not exist $(KERNEL_LOADER_DLL) (echo Missing dependency: $(KERNEL_LOADER_DLL) & exit /b 1)
	copy /Y $(AESLIB_DLL) build\bin\ >nul || exit /b 1
	copy /Y $(KERNEL_LOADER_DLL) build\bin\ >nul || exit /b 1
else
	test -f $(AESLIB_DLL) || (echo "Missing dependency: $(AESLIB_DLL)"; exit 1)
	test -f $(KERNEL_LOADER_DLL) || (echo "Missing dependency: $(KERNEL_LOADER_DLL)"; exit 1)
	mkdir -p build/bin
	cp -f $(AESLIB_DLL) build/bin/
	cp -f $(KERNEL_LOADER_DLL) build/bin/
endif

build_dirs:
	$(MKDIR_BUILD)
	$(MKDIR_OBJ)
	$(MKDIR_BIN)
	$(MKDIR_LIB)

copy_kernels: build_dirs
	$(COPY_KERNELS)

lib: $(LIB_STATIC)

shared: deps $(SHARED_LIB) copy_kernels copy_deps

test: deps $(TEST_BIN) copy_kernels copy_deps

bench: deps $(BENCH_BIN) copy_kernels copy_deps

profile: deps $(PROFILE_BIN) copy_kernels copy_deps

$(LIB_STATIC): build_dirs $(OBJ)
	$(AR) rcs $(LIB_STATIC) $(OBJ)

build/obj/%.o: src/%.c build_dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_OBJ): $(TEST_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(TEST_SRC) -o $(TEST_OBJ)

$(TEST_BIN): build_dirs $(LIB_STATIC) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) $(LIB_STATIC) -o $(TEST_BIN) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)

$(BENCH_OBJ): $(BENCH_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(BENCH_SRC) -o $(BENCH_OBJ)

$(BENCH_BIN): build_dirs $(LIB_STATIC) $(BENCH_OBJ)
	$(CC) $(CFLAGS) $(BENCH_OBJ) $(LIB_STATIC) -o $(BENCH_BIN) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)

$(PROFILE_OBJ): $(PROFILE_SRC) build_dirs
	$(CC) $(CFLAGS) -c $(PROFILE_SRC) -o $(PROFILE_OBJ)

$(PROFILE_BIN): build_dirs $(LIB_STATIC) $(PROFILE_OBJ)
	$(CC) $(CFLAGS) $(PROFILE_OBJ) $(LIB_STATIC) -o $(PROFILE_BIN) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)

ifeq ($(OS),Windows_NT)
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) -Wl,--out-implib,$(IMPORT_LIB) -Wl,--export-all-symbols $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)
else
$(SHARED_LIB): build_dirs $(OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(OBJ) $(LDFLAGS) $(OPENCL_LIBS) $(DEPS_LDFLAGS)
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
