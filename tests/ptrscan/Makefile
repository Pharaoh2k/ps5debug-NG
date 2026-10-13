# Host build of the pointer-scan handler + test server (no console, no SDK needed).
#   make            build ./harness
#   make test       build and run test_ptrscan.py
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
SRC      = ../../debugger/source/ptr_scan.c ../../debugger/source/ptr_scan_core.c harness.c
INC      = -Istubs -I../../common/include -I../../debugger/include

harness: $(SRC) stubs/sdk_shim.h ../../debugger/include/ptr_scan.h ../../common/include/protocol.h
	$(CC) $(CFLAGS) $(INC) -o $@ $(SRC)

test: harness
	python3 test_ptrscan.py

clean:
	rm -f harness

.PHONY: test clean
