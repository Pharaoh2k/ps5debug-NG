// SPDX-License-Identifier: GPL-3.0-only
//
// Pointer-scan level (opcode 0xBDAACC30, raw literal, needs auth).
//
// One pass over the given data segments of a process: report every 8-byte aligned
// slot whose value v satisfies   f - max_off <= v <= f   for some address f of the
// client's sorted "frontier".  The client walks level by level (target -> pointers
// to it -> pointers to those ...), so only the matches ever cross the network.
//
// Request  (packet data, 24 bytes): struct cmd_proc_ptrscan_packet
// Reply    CMD_SUCCESS                         (header accepted)
//          <- client sends nseg x {u64 addr; u64 len}, then nfront x u64 (ascending)
//          CMD_SUCCESS | CMD_DATA_NULL          (inputs accepted / rejected)
//          stream of blocks:  u32 n;  n x {u64 slot_addr; u64 value}
//                             n == 0xFFFFFFFF -> progress: u64 bytes_done, u64 bytes_total
//                             n == 0          -> end
//          u64 total_hits; u64 bytes_scanned; u32 status (0 ok, 1 cancelled, 2 hit cap)
//          CMD_SUCCESS
// Cancel:  0xBDAACC17 (turbo cancel) for the same pid, from another connection.
#pragma once
#include <stdint.h>
#include <stddef.h>

#define PTRSCAN_FLAG_ALIAS     0x1u      /* use the aliasing read engine (falls back to mdbg per chunk) */

#define PTRSCAN_MAX_FRONT      (8u << 20)   /* 8M addresses (64 MB) */
#define PTRSCAN_MAX_SEGS       65536u
#define PTRSCAN_MAX_OFF        0x100000ULL  /* 1 MB */
#define PTRSCAN_MAX_HITS       (64ULL << 20)

#define TSE_POINTER_SCAN       0x00001000u  /* CAPS engine bit: 0xBDAACC30 is available */

struct cmd_proc_ptrscan_packet {
    uint32_t pid;
    uint32_t flags;
    uint64_t max_off;
    uint32_t nseg;
    uint32_t nfront;
} __attribute__((packed));

/* ---- core (pure C, no console APIs - unit-testable on a PC) ---- */
#define PTRSCAN_BM_BITS   27u                       /* bitmap over (value >> 12): 2^27 bits = 16 MB */
#define PTRSCAN_BM_BYTES  ((size_t)1 << (PTRSCAN_BM_BITS - 3))

struct ptrscan_core {
    const uint64_t *f;      /* frontier, ascending */
    uint64_t n;
    uint64_t max_off;
    uint64_t lo, hi;        /* quick reject: [f[0]-max_off, f[n-1]] */
    uint8_t *bm;            /* PTRSCAN_BM_BYTES, caller-owned */
};

/* Prepare `c` (fills the page bitmap).  Returns 0, or -1 if the frontier is not ascending. */
int ptrscan_core_init(struct ptrscan_core *c, const uint64_t *f, uint64_t n, uint64_t max_off, uint8_t *bm);

/* Is v a pointer to (just below) some frontier address? */
static inline int ptrscan_core_hit(const struct ptrscan_core *c, uint64_t v) {
    if (v < c->lo || v > c->hi) return 0;
    uint64_t pg = (v >> 12) & (((uint64_t)1 << PTRSCAN_BM_BITS) - 1);
    if (!(c->bm[pg >> 3] & (uint8_t)(1u << (pg & 7)))) return 0;
    uint64_t lo = 0, hi = c->n;
    while (lo < hi) {
        uint64_t mid = lo + ((hi - lo) >> 1);
        if (c->f[mid] < v) lo = mid + 1; else hi = mid;
    }
    return lo < c->n && c->f[lo] - v <= c->max_off;
}

/* Scan one buffer of `len` bytes that holds target memory starting at `addr` (8-aligned).
 * Calls emit(user, slot_addr, value) per hit; returns the number of hits. */
typedef void (*ptrscan_emit_fn)(void *user, uint64_t slot_addr, uint64_t value);
uint64_t ptrscan_core_block(const struct ptrscan_core *c, const uint8_t *src, uint64_t len,
                            uint64_t addr, ptrscan_emit_fn emit, void *user);

struct cmd_packet;
int proc_ptrscan_handle(int fd, struct cmd_packet *packet);
