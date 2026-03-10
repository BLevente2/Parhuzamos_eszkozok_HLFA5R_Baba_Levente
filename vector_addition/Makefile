SHELL := cmd.exe
.SHELLFLAGS := /C

CC := gcc

BUILD_DIR := build
EXE := $(BUILD_DIR)\app.exe

KERNEL_LOADER_ROOT ?= ../kernel_loader
KERNEL_LOADER_DIR := $(KERNEL_LOADER_ROOT)

ifeq ($(strip $(wildcard $(KERNEL_LOADER_DIR)/include/kernel_loader.h)),)
ifneq ($(strip $(wildcard $(KERNEL_LOADER_DIR)/kernel_loader/include/kernel_loader.h)),)
KERNEL_LOADER_DIR := $(KERNEL_LOADER_DIR)/kernel_loader
endif
endif

KERNEL_LOADER_DIR_WIN := $(subst /,\,$(KERNEL_LOADER_DIR))

CFLAGS := -std=c99 -O2 -Iinclude -I$(KERNEL_LOADER_DIR)/include
LDFLAGS := -L$(KERNEL_LOADER_DIR)/build -lkernel_loader -lOpenCL -lm

SRC_MAIN := main.c
SRC_EXTRA := $(wildcard src/*.c)

OBJ := $(BUILD_DIR)\main.o
ifneq ($(strip $(SRC_EXTRA)),)
OBJ += $(patsubst src/%.c,$(BUILD_DIR)\%.o,$(SRC_EXTRA))
endif

.PHONY: all run clean

all: $(EXE)

$(EXE): $(OBJ)
	if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	$(CC) -o $(EXE) $(OBJ) $(LDFLAGS)
	if exist "$(KERNEL_LOADER_DIR_WIN)\build\kernel_loader.dll" copy /Y "$(KERNEL_LOADER_DIR_WIN)\build\kernel_loader.dll" "$(BUILD_DIR)\kernel_loader.dll" >NUL
	if exist "kernels" xcopy /E /I /Y "kernels" "$(BUILD_DIR)\kernels" >NUL

$(BUILD_DIR)\main.o: main.c
	if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD_DIR)\%.o: src/%.c
	if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	$(CC) -c -o $@ $< $(CFLAGS)

run: all
	$(EXE)

clean:
	if exist "$(BUILD_DIR)" rmdir /S /Q "$(BUILD_DIR)"