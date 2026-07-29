// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include <stdint.h>

#define PS5DEBUG_WRITE_PATH_AUTO 0
#define PS5DEBUG_WRITE_PATH_DMAP 1
#define PS5DEBUG_WRITE_PATH_MDBG 2

#ifndef PS5DEBUG_FORCE_WRITE_PATH
#define PS5DEBUG_FORCE_WRITE_PATH PS5DEBUG_WRITE_PATH_AUTO
#endif

#ifndef PS5DEBUG_WRITE_DIAGNOSTICS
#define PS5DEBUG_WRITE_DIAGNOSTICS 0
#endif

#if PS5DEBUG_FORCE_WRITE_PATH < PS5DEBUG_WRITE_PATH_AUTO \
    || PS5DEBUG_FORCE_WRITE_PATH > PS5DEBUG_WRITE_PATH_MDBG
#error "PS5DEBUG_FORCE_WRITE_PATH must be 0 (auto), 1 (DMAP), or 2 (mdbg)"
#endif

static inline int ps5debug_write_needs_prefix(uint64_t address)
{
    /* The workaround preserves address-1 with a non-atomic read-modify-write. */
    return (address & 0xFFu) == 0xFFu;
}

static inline int ps5debug_write_diagnostics_enabled(void)
{
    return PS5DEBUG_WRITE_DIAGNOSTICS;
}
