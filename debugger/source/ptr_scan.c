// SPDX-License-Identifier: GPL-3.0-only
// Pointer-scan level handler (0xBDAACC30) - see ptr_scan.h for the wire format.

#include "ptr_scan.h"
#include "scan_alias.h"
#include "protocol.h"
#include "proc.h"
#include "net.h"
#include "sdk_shim.h"

extern volatile int g_turboscan_cancel_pid;      /* scan_turbo.c - set by 0xBDAACC17 */
extern long __crt_syscall(long sysno, ...);
int klog_puts(const char *s);
int snprintf(char *str, size_t size, const char *format, ...);

/* Big buffers come from mmap like turbo scan's (the payload's malloc heap is small). */
static void *ps_map(uint64_t n) {
    n = (n + 0xFFFULL) & ~0xFFFULL;
    void *m = (void *)__crt_syscall(477, 0L, (long)n, 3L, 0x1002L, -1L, 0L);
    return (m == (void *)-1) ? (void *)0 : m;
}
static void ps_unmap(void *p, uint64_t n) {
    if (p) __crt_syscall(73, (long)p, (long)((n + 0xFFFULL) & ~0xFFFULL));
}
static void ps_log(const char *what, uint64_t a, uint64_t b) {
    char line[160];
    snprintf(line, sizeof(line), "[ps5debug-NG ptrscan] %s (%llu, %llu)\n", what,
             (unsigned long long)a, (unsigned long long)b);
    klog_puts(line);
}

#define PS_CHUNK      0x100000ULL                /* 1 MB per read (aliasing maps <= 511 pages) */
#define PS_OUT_CAP    0x40000u                   /* streamed result block */
#define PS_PROGRESS   (256ULL << 20)             /* progress record every 256 MB */

struct ps_out {
    int fd;
    uint8_t *buf;
    uint32_t n;                                  /* records in buf (after the 4-byte header) */
    uint64_t total;
    int capped;
};

static void ps_flush(struct ps_out *o) {
    if (!o->n) return;
    __builtin_memcpy(o->buf, &o->n, 4);
    net_send_all(o->fd, o->buf, (int)(4 + (uint64_t)o->n * 16));
    o->n = 0;
}

static void ps_emit(void *user, uint64_t slot, uint64_t value) {
    struct ps_out *o = (struct ps_out *)user;
    if (o->total >= PTRSCAN_MAX_HITS) { o->capped = 1; return; }
    if (4 + ((uint64_t)o->n + 1) * 16 > PS_OUT_CAP) ps_flush(o);
    uint8_t *r = o->buf + 4 + (uint64_t)o->n * 16;
    __builtin_memcpy(r, &slot, 8);
    __builtin_memcpy(r + 8, &value, 8);
    o->n++;
    o->total++;
}

static void ps_progress(int fd, uint64_t done, uint64_t total) {
    uint8_t rec[20];
    uint32_t mark = 0xFFFFFFFFu;
    __builtin_memcpy(rec, &mark, 4);
    __builtin_memcpy(rec + 4, &done, 8);
    __builtin_memcpy(rec + 12, &total, 8);
    net_send_all(fd, rec, 20);
}

int proc_ptrscan_handle(int fd, struct cmd_packet *packet) {
    /* Rejections before the ack leave the stream in sync (the client sends nothing more), so they
     * return 0 and keep the connection open. */
    if (!(g_proc_auth_state & 2)) { ps_log("not authenticated", 0, 0); net_send_int32(fd, CMD_DATA_NULL); return 0; }
    struct cmd_proc_ptrscan_packet *pp = (struct cmd_proc_ptrscan_packet *)packet->data;
    if (!pp || packet->datalen < sizeof(*pp)) {
        ps_log("short request", packet->datalen, sizeof(*pp)); net_send_int32(fd, CMD_DATA_NULL); return 0;
    }
    uint32_t pid = pp->pid, nseg = pp->nseg, nfront = pp->nfront, flags = pp->flags;
    uint64_t max_off = pp->max_off;
    if (pid == 0 || nseg == 0 || nseg > PTRSCAN_MAX_SEGS || nfront == 0 || nfront > PTRSCAN_MAX_FRONT
        || max_off > PTRSCAN_MAX_OFF) {
        ps_log("bad request: segments / frontier", nseg, nfront);
        net_send_int32(fd, CMD_DATA_NULL); return 0;
    }

    uint64_t segs_n = (uint64_t)nseg * 16, front_n = (uint64_t)nfront * 8;
    uint64_t *segs  = (uint64_t *)ps_map(segs_n);
    uint64_t *front = (uint64_t *)ps_map(front_n);
    uint8_t  *bm    = (uint8_t *)ps_map(PTRSCAN_BM_BYTES);
    uint8_t  *rbuf  = (uint8_t *)ps_map(PS_CHUNK);
    uint8_t  *obuf  = (uint8_t *)ps_map(PS_OUT_CAP);
#define PS_FREE_ALL() do { ps_unmap(segs, segs_n); ps_unmap(front, front_n); ps_unmap(bm, PTRSCAN_BM_BYTES); \
                           ps_unmap(rbuf, PS_CHUNK); ps_unmap(obuf, PS_OUT_CAP); } while (0)
    if (!segs || !front || !bm || !rbuf || !obuf) {
        ps_log("out of memory", segs_n + front_n, PTRSCAN_BM_BYTES);
        PS_FREE_ALL();
        net_send_int32(fd, CMD_DATA_NULL); return 0;
    }
    if (g_turboscan_cancel_pid == (int)pid) g_turboscan_cancel_pid = 0;   /* drop a stale cancel */

    net_send_int32(fd, CMD_SUCCESS);
    int rx = net_recv_all(fd, segs, (int)((size_t)nseg * 16), 1);
    if (rx == 0) rx = net_recv_all(fd, front, (int)((size_t)nfront * 8), 1);

    struct ptrscan_core core;
    if (rx != 0 || ptrscan_core_init(&core, front, nfront, max_off, bm) != 0) {
        ps_log(rx != 0 ? "receive failed" : "frontier not ascending", nseg, nfront);
        net_send_int32(fd, CMD_DATA_NULL);
        PS_FREE_ALL();
        return rx != 0;                          /* a broken receive desyncs the stream: drop it */
    }
    net_send_int32(fd, CMD_SUCCESS);

    uint64_t total_bytes = 0;
    for (uint32_t i = 0; i < nseg; i++) total_bytes += segs[i * 2 + 1];

    scan_alias_ctx *actx = (flags & PTRSCAN_FLAG_ALIAS) ? scan_alias_begin(pid, 64ULL << 20) : (scan_alias_ctx *)0;
    struct ps_out out = { fd, obuf, 0, 0, 0 };
    uint64_t done = 0, next_prog = PS_PROGRESS;
    uint32_t status = 0;

    for (uint32_t i = 0; i < nseg && !status; i++) {
        uint64_t a = segs[i * 2], len = segs[i * 2 + 1];
        uint64_t end = a + len;
        a = (a + 7) & ~7ULL;
        while (a + 8 <= end) {
            int c = g_turboscan_cancel_pid;
            if (c != 0 && c == (int)pid) { status = 1; break; }
            if (out.capped) { status = 2; break; }
            uint64_t n = end - a;
            if (n > PS_CHUNK) n = PS_CHUNK;
            n &= ~7ULL;
            const uint8_t *src = actx ? (const uint8_t *)scan_alias_map(actx, a, n, (uint64_t *)0)
                                      : (const uint8_t *)0;
            int mapped = src != 0;
            if (!mapped) {
                __builtin_memset(rbuf, 0, n);
                proc_read_mem(pid, a, n, rbuf);
                src = rbuf;
            }
            ptrscan_core_block(&core, src, n, a, ps_emit, &out);
            if (mapped) scan_alias_release(actx);
            a += n;
            done += n;
            if (done >= next_prog) {
                ps_flush(&out);
                ps_progress(fd, done, total_bytes);
                next_prog = done + PS_PROGRESS;
            }
        }
    }
    if (actx) scan_alias_end(actx);

    ps_flush(&out);
    uint32_t zero = 0;
    net_send_all(fd, &zero, 4);
    net_send_all(fd, &out.total, 8);
    net_send_all(fd, &done, 8);
    net_send_all(fd, &status, 4);
    net_send_int32(fd, CMD_SUCCESS);

    PS_FREE_ALL();
    return 0;
}
