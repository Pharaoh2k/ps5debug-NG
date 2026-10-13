// SPDX-License-Identifier: GPL-3.0-only
// Pointer-scan level handler (0xBDAACC30) - see ptr_scan.h for the wire format.

#include "ptr_scan.h"
#include "scan_alias.h"
#include "protocol.h"
#include "proc.h"
#include "net.h"
#include "sdk_shim.h"

extern volatile int g_turboscan_cancel_pid;      /* scan_turbo.c - set by 0xBDAACC17 */

/* Big buffers come from mmap like turbo scan's (the payload's malloc heap is small). */
static void *ps_map(uint64_t n) {
    n = (n + 0xFFFULL) & ~0xFFFULL;
    void *m = (void *)__crt_syscall(477, 0L, (long)n, 3L, 0x1002L, -1L, 0L);
    return (m == (void *)-1 || m == (void *)0) ? (void *)0 : m;
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
#define PS_PAGE       0x1000ULL                  /* retry granularity after a failed chunk read */
#define PS_OUT_CAP    0x40000u                   /* streamed result block */
#define PS_PROGRESS   (256ULL << 20)             /* progress record every 256 MB */
#define PS_PEER_EVERY 16                         /* chunks between "is the client still there" checks */
#define PS_USER_TOP   0x0000800000000000ULL      /* end of the canonical user half */

struct ps_out {
    int fd;
    uint8_t *buf;
    uint32_t n;                                  /* records in buf (after the 4-byte header) */
    uint64_t total;
    int capped;                                  /* a match was dropped at PTRSCAN_MAX_HITS */
    int err;                                     /* a send failed: the client is gone */
};

static void ps_flush(struct ps_out *o) {
    if (!o->n || o->err) { o->n = 0; return; }
    __builtin_memcpy(o->buf, &o->n, 4);
    if (net_send_all(o->fd, o->buf, (int)(4 + (uint64_t)o->n * 16)) != 0) o->err = 1;
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

static void ps_progress(struct ps_out *o, uint64_t done, uint64_t total) {
    if (o->err) return;
    uint8_t rec[20];
    uint32_t mark = 0xFFFFFFFFu;
    __builtin_memcpy(rec, &mark, 4);
    __builtin_memcpy(rec + 4, &done, 8);
    __builtin_memcpy(rec + 12, &total, 8);
    if (net_send_all(o->fd, rec, 20) != 0) o->err = 1;
}

/* The client sends nothing while a pass runs, so the socket only becomes readable when the client
 * has closed it (EOF) or reset it.  select() with a zero timeout first, like handle_client, so the
 * peek can never block. */
static int ps_peer_closed(int fd) {
    struct timeval tv;
    fd_set rfd;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&rfd);
    FD_SET(fd, &rfd);
    if (select(fd + 1, &rfd, NULL, NULL, &tv) <= 0 || !FD_ISSET(fd, &rfd)) return 0;
    char b;
    return recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT) <= 0;
}

/* Reject before the ack: nothing more is coming from the client, so the stream stays in sync and
 * the connection can stay open (return 0) - unless the reply itself could not be sent. */
static int ps_reject(int fd, const char *why, uint64_t a, uint64_t b) {
    ps_log(why, a, b);
    return net_send_int32(fd, CMD_DATA_NULL) != 0;
}

int proc_ptrscan_handle(int fd, struct cmd_packet *packet) {
    if (!(g_proc_auth_state & 2)) return ps_reject(fd, "not authenticated", 0, 0);
    struct cmd_proc_ptrscan_packet *pp = (struct cmd_proc_ptrscan_packet *)packet->data;
    if (!pp || packet->datalen < sizeof(*pp)) return ps_reject(fd, "short request", packet->datalen, sizeof(*pp));
    uint32_t pid = pp->pid, nseg = pp->nseg, nfront = pp->nfront, flags = pp->flags;
    uint64_t max_off = pp->max_off;
    if (flags & ~PTRSCAN_FLAGS_KNOWN) return ps_reject(fd, "unknown flag bits", flags, PTRSCAN_FLAGS_KNOWN);
    if (pid == 0 || nseg == 0 || nseg > PTRSCAN_MAX_SEGS || nfront == 0 || nfront > PTRSCAN_MAX_FRONT
        || max_off > PTRSCAN_MAX_OFF)
        return ps_reject(fd, "bad request: segments / frontier / max_off", nseg, nfront);

    uint64_t segs_n = (uint64_t)nseg * 16, front_n = (uint64_t)nfront * 8;
    uint64_t *segs  = (uint64_t *)ps_map(segs_n);
    uint64_t *front = (uint64_t *)ps_map(front_n);
    uint8_t  *bm    = (uint8_t *)ps_map(PTRSCAN_BM_BYTES);
    uint8_t  *rbuf  = (uint8_t *)ps_map(PS_CHUNK);
    uint8_t  *obuf  = (uint8_t *)ps_map(PS_OUT_CAP);
#define PS_FREE_ALL() do { ps_unmap(segs, segs_n); ps_unmap(front, front_n); ps_unmap(bm, PTRSCAN_BM_BYTES); \
                           ps_unmap(rbuf, PS_CHUNK); ps_unmap(obuf, PS_OUT_CAP); } while (0)
    if (!segs || !front || !bm || !rbuf || !obuf) {
        PS_FREE_ALL();
        return ps_reject(fd, "out of memory", segs_n + front_n, PTRSCAN_BM_BYTES);
    }
    if (g_turboscan_cancel_pid == (int)pid) g_turboscan_cancel_pid = 0;   /* drop a stale cancel */

    if (net_send_int32(fd, CMD_SUCCESS) != 0) { PS_FREE_ALL(); return 1; }
    if (net_recv_all(fd, segs, (int)segs_n, 1) != 0 || net_recv_all(fd, front, (int)front_n, 1) != 0) {
        ps_log("receive failed", nseg, nfront);
        PS_FREE_ALL();
        return 1;                                /* a broken receive desyncs the stream: drop it */
    }

    /* Inputs are complete from here on, so a rejection keeps the stream in sync. */
    uint64_t total_bytes = 0;
    const char *bad = (const char *)0;
    uint64_t bad_a = 0, bad_b = 0;
    for (uint32_t i = 0; i < nseg && !bad; i++) {
        uint64_t sa = segs[i * 2], sl = segs[i * 2 + 1];
        if (sl > ~0ULL - sa || sa + sl > PS_USER_TOP) { bad = "segment wraps or leaves user space"; bad_a = sa; bad_b = sl; }
        total_bytes += sl;
    }
    struct ptrscan_core core;
    if (!bad && ptrscan_core_init(&core, front, nfront, max_off, bm) != 0) { bad = "frontier not ascending"; bad_a = nfront; }
    if (bad) {
        ps_log(bad, bad_a, bad_b);
        int rc = net_send_int32(fd, CMD_DATA_NULL) != 0;
        PS_FREE_ALL();
        return rc;
    }
    if (net_send_int32(fd, CMD_SUCCESS) != 0) { PS_FREE_ALL(); return 1; }

    scan_alias_ctx *actx = (scan_alias_ctx *)0;
    if (flags & PTRSCAN_FLAG_ALIAS) {
        /* page-table discovery has to have run once, or aliasing silently falls back (as turbo does) */
        uint64_t pp_ = 0, ps_ = 0, pe_ = 0; int pl_ = 0;
        proc_ptwalk_probe(pid, segs[0], &pp_, &pl_, &ps_, &pe_);
        actx = scan_alias_begin(pid, 64ULL << 20);
    }
    struct ps_out out = { fd, obuf, 0, 0, 0, 0 };
    uint64_t done = 0, scanned = 0, unreadable = 0, next_prog = PS_PROGRESS;
    uint32_t status = PTRSCAN_ST_OK, chunks = 0;

    for (uint32_t i = 0; i < nseg && status == PTRSCAN_ST_OK && !out.err; i++) {
        uint64_t a = segs[i * 2], end = a + segs[i * 2 + 1];
        a = (a + 7) & ~7ULL;
        while (a < end && end - a >= 8) {
            int c = g_turboscan_cancel_pid;
            if (c != 0 && c == (int)pid) { status = PTRSCAN_ST_CANCELLED; break; }
            if (++chunks % PS_PEER_EVERY == 0 && ps_peer_closed(fd)) { out.err = 1; break; }
            uint64_t n = end - a;
            if (n > PS_CHUNK) n = PS_CHUNK;
            n &= ~7ULL;
            const uint8_t *src = actx ? (const uint8_t *)scan_alias_map(actx, a, n, (uint64_t *)0)
                                      : (const uint8_t *)0;
            if (src) {
                ptrscan_core_block(&core, src, n, a, ps_emit, &out);
                scan_alias_release(actx);
                scanned += n;
            } else if (proc_read_mem_checked(pid, a, n, rbuf) == 0) {
                ptrscan_core_block(&core, rbuf, n, a, ps_emit, &out);
                scanned += n;
            } else {
                /* part of the chunk is unreadable (unmapped mid-pass, process exiting ...):
                 * retry page by page, skip what still fails and report it as unread */
                for (uint64_t off = 0; off < n;) {
                    uint64_t pa = a + off;
                    uint64_t piece = PS_PAGE - (pa & (PS_PAGE - 1));
                    if (piece > n - off) piece = n - off;
                    if (proc_read_mem_checked(pid, pa, piece, rbuf) == 0) {
                        ptrscan_core_block(&core, rbuf, piece, pa, ps_emit, &out);
                        scanned += piece;
                    } else {
                        unreadable += piece;
                    }
                    off += piece;
                }
            }
            a += n;
            done += n;
            if (out.capped) { status = PTRSCAN_ST_CAPPED; break; }
            if (out.err) break;
            if (done >= next_prog) {
                ps_flush(&out);
                ps_progress(&out, done, total_bytes);
                next_prog = done + PS_PROGRESS;
            }
        }
    }
    if (actx) scan_alias_end(actx);
    if (out.capped && status == PTRSCAN_ST_OK) status = PTRSCAN_ST_CAPPED;

    ps_flush(&out);
    if (out.err) {
        ps_log("client gone, pass stopped", done, total_bytes);
        PS_FREE_ALL();
        return 1;                                /* handle_client closes the connection */
    }
    uint32_t zero = 0;
    int rc = net_send_all(fd, &zero, 4)
          | net_send_all(fd, &out.total, 8)
          | net_send_all(fd, &scanned, 8)
          | net_send_all(fd, &unreadable, 8)
          | net_send_all(fd, &status, 4)
          | net_send_int32(fd, CMD_SUCCESS);
    PS_FREE_ALL();
    return rc != 0;
}
