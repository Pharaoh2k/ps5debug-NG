// SPDX-License-Identifier: GPL-3.0-only
// Pointer-scan matching core: pure C, no console APIs (also compiled natively for tests).

#include "ptr_scan.h"

int ptrscan_core_init(struct ptrscan_core *c, const uint64_t *f, uint64_t n, uint64_t max_off, uint8_t *bm) {
    c->f = f;
    c->n = n;
    c->max_off = max_off;
    c->bm = bm;
    __builtin_memset(bm, 0, PTRSCAN_BM_BYTES);
    if (n == 0) { c->lo = 1; c->hi = 0; return 0; }
    for (uint64_t i = 1; i < n; i++)
        if (f[i] < f[i - 1]) return -1;
    c->lo = f[0] > max_off ? f[0] - max_off : 0;
    c->hi = f[n - 1];
    const uint64_t mask = ((uint64_t)1 << PTRSCAN_BM_BITS) - 1;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t a = f[i] > max_off ? f[i] - max_off : 0;
        uint64_t p0 = a >> 12, p1 = f[i] >> 12;
        for (uint64_t p = p0; p <= p1; p++) {
            uint64_t b = p & mask;
            bm[b >> 3] |= (uint8_t)(1u << (b & 7));
        }
    }
    return 0;
}

uint64_t ptrscan_core_block(const struct ptrscan_core *c, const uint8_t *src, uint64_t len,
                            uint64_t addr, ptrscan_emit_fn emit, void *user) {
    uint64_t hits = 0;
    uint64_t words = len >> 3;
    const uint64_t lo = c->lo, hi = c->hi;
    for (uint64_t i = 0; i < words; i++) {
        uint64_t v;
        __builtin_memcpy(&v, src + (i << 3), 8);
        if (v < lo || v > hi) continue;           /* the common case: one compare pair */
        if (!ptrscan_core_hit(c, v)) continue;
        emit(user, addr + (i << 3), v);
        hits++;
    }
    return hits;
}
