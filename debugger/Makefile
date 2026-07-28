# SPDX-License-Identifier: GPL-3.0-only

SDK := ../ps5-payload-sdk/install

ifeq (,$(wildcard $(SDK)/toolchain/prospero.mk))
    $(error SDK not built - run ../build.sh from the project root)
endif

include $(SDK)/toolchain/prospero.mk

ELF       := build/debugger.elf
BUILD_DIR := build

ZYDIR     := third_party/zydis
ZYDIS_OBJ := $(BUILD_DIR)/Zydis.o

KSDIR    := third_party/keystone
CXXRT    := third_party/cxxrt

CFLAGS  := -Wall -O2 -I../common/include -Iinclude -I$(ZYDIR) -I$(KSDIR)/include
LDFLAGS := -Wl,--wrap=__patch_init
LDLIBS  := -lSceLibcInternal -lkernel_sys -lSceNet -lSceNetCtl -lSceSysCore

WRITE_DIAG       ?= 0
WRITE_PATH       ?= 0
BUILD_FINGERPRINT ?= unfingerprinted
CFLAGS += -DPS5DEBUG_WRITE_DIAGNOSTICS=$(WRITE_DIAG)
CFLAGS += -DPS5DEBUG_FORCE_WRITE_PATH=$(WRITE_PATH)
CFLAGS += -DPS5DEBUG_NG_BUILD_FINGERPRINT_STR=\"$(BUILD_FINGERPRINT)\"

ZYDIS_CFLAGS := -O3 -DNDEBUG -DZYAN_NO_LIBC -w -I../common/include -Iinclude -I$(ZYDIR)

CXXFILES   := $(wildcard source/*.cpp)
CXX_OBJS   := $(patsubst source/%.cpp,$(BUILD_DIR)/%.o,$(CXXFILES))
CXXFLAGS   := -O2 -I../common/include -Iinclude -I$(KSDIR)/include
CXX_LDLIBS := -Wl,--start-group -L$(KSDIR)/lib -L$(CXXRT)/lib -lkeystone -lc++ -lc++abi -lunwind -Wl,--end-group

CFILES := $(wildcard ../common/source/*.c) $(wildcard source/*.c)

all: $(ELF)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(ZYDIS_OBJ): $(ZYDIR)/Zydis.c $(ZYDIR)/Zydis.h | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(ZYDIS_CFLAGS)

$(BUILD_DIR)/%.o: source/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(ELF): $(CFILES) $(CXX_OBJS) $(ZYDIS_OBJ) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(CFILES) $(CXX_OBJS) $(ZYDIS_OBJ) $(LDFLAGS) $(LDLIBS) $(CXX_LDLIBS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
