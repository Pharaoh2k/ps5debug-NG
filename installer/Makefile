# SPDX-License-Identifier: GPL-3.0-only

SDK := ../ps5-payload-sdk/install

ifeq (,$(wildcard $(SDK)/toolchain/prospero.mk))
    $(error SDK not built - run ../build.sh from the project root)
endif

include $(SDK)/toolchain/prospero.mk

ELF       := build/ps5debug-NG.elf
BUILD_DIR := build

PAYLOAD_ELF  := ../debugger/build/debugger.elf
EMBEDDED_BIN := $(BUILD_DIR)/embedded_inner.elf.bin
EMBEDDED_OBJ := $(BUILD_DIR)/embedded_inner.o
EMBEDDED_S   := source/embedded_inner.S

CFLAGS  := -Wall -O2 -I../common/include -ffunction-sections -fdata-sections
LDFLAGS := -Wl,--gc-sections
LDLIBS  := -lSceLibcInternal -lkernel_sys -lSceNet -lSceNetCtl -lSceSysCore

WRITE_DIAG        ?= 0
WRITE_PATH        ?= 0
BUILD_FINGERPRINT ?= unfingerprinted
CFLAGS += -DPS5DEBUG_WRITE_DIAGNOSTICS=$(WRITE_DIAG)
CFLAGS += -DPS5DEBUG_FORCE_WRITE_PATH=$(WRITE_PATH)
CFLAGS += -DPS5DEBUG_NG_BUILD_FINGERPRINT_STR=\"$(BUILD_FINGERPRINT)\"

CFILES := $(wildcard ../common/source/*.c) $(wildcard source/*.c)

all: $(ELF)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(EMBEDDED_BIN): $(PAYLOAD_ELF) | $(BUILD_DIR)
	cp $< $@

$(EMBEDDED_OBJ): $(EMBEDDED_S) $(EMBEDDED_BIN) | $(BUILD_DIR)
	$(CC) -c -o $@ $(EMBEDDED_S) -I$(BUILD_DIR)

$(ELF): $(CFILES) $(EMBEDDED_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(CFILES) $(EMBEDDED_OBJ) $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
