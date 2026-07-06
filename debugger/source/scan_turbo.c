// SPDX-License-Identifier: GPL-3.0-only


#include "scan_turbo.h"
#include "scan_alias.h"
#include "protocol.h"
#include "proc.h"
#include "net.h"
#include "sdk_shim.h"

#define TS_WORKER_THREADS 4

static double sf_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int scan_turbo_regions(uint32_t pid, int mode, uint32_t min_mbps,
                      struct scan_range *out, int max, uint64_t *out_total_bytes) {
    if (out_total_bytes) *out_total_bytes = 0;
    if (!out || max <= 0) return 0;

    void *maps = NULL;
    int count = 0;
    if (sys_proc_vm_map(pid, &maps, &count) != 0 || count <= 0) return 0;

    struct proc_vm_map_entry *e = (struct proc_vm_map_entry *)maps;
    uint8_t *probe = (mode == SCAN_EXCLUDE_SPEED) ? (uint8_t *)malloc(65536) : NULL;
    int n = 0;
    uint64_t total = 0;

    for (int i = 0; i < count && n < max; i++) {
        if (!(e[i].prot & 1)) continue;
        uint64_t st = e[i].start, en = e[i].end;
        if (en <= st) continue;

        if (mode == SCAN_EXCLUDE_PCD) {
            uint64_t pte = 0, ph = 0, pg = 0; int lv = -1;
            if (proc_ptwalk_probe(pid, st, &ph, &lv, &pg, &pte) == 0 && ((pte >> 4) & 1))
                continue;
        } else if (mode == SCAN_EXCLUDE_SPEED && probe) {
            uint64_t pb = (en - st) < 65536 ? (en - st) : 65536;
            double t0 = sf_now();
            proc_read_mem(pid, st, pb, probe);
            double t1 = sf_now();
            double dt = t1 - t0;
            double mbps = dt > 0 ? ((double)pb / 1e6) / dt : 1e9;
            if (mbps < (double)min_mbps) continue;
        }

        out[n].start = st;
        out[n].end   = en;
        n++;
        total += (en - st);
    }

    if (probe) free(probe);
    if (out_total_bytes) *out_total_bytes = total;
    free(maps);
    return n;
}

#define TS_MAX_CLIENTS   12
#define TS_RESIDENT_CAP  (256ULL << 20)

#define TS_MODE_NONE     0
#define TS_MODE_LIST     1
#define TS_MODE_SNAPSHOT 2

#define TS_SNAP_BITMAP_MAX (448ULL << 20)

#define TS_SNAP_RAM_DEFAULT (512ULL << 20)

#define TS_SNAP_IO_CHUNK    (16ULL << 20)

#define TS_MATERIALIZE_COUNT_MAX (1ULL << 20)
#define TS_MATERIALIZE_DENSITY    32ULL

#define TS_RESCAN_GAP_MAX  0x8000ULL
#define TS_RESCAN_WIN_CAP  0x100000ULL

/* TS_RESCAN_ALIASING (client opt-in, protocol.h): the rescan reads full-size (bridging) survivor
   windows via the aliasing engine instead of mdbg; tiny scattered windows (< TS_RESCAN_ALIAS_MIN_WIN,
   where per-window alias setup would exceed the read) and any alias failure fall back to mdbg (the
   floor). Bounded: one window mapped+released at a time. */
#define TS_RESCAN_ALIAS_MIN_WIN 0x10000ULL

#define TS_SNAP_MAX_SEGS   (1u << 20)

struct fs_segment {
    uint64_t addr;
    uint64_t slot_start;
    uint64_t nslots;
};

struct turboscan_session {
    int      in_use;
    int      mode;

    void    *buf;
    uint64_t buf_cap;
    uint64_t count;
    uint64_t rec_size;

    uint8_t *bitmap;
    uint64_t bitmap_bytes;
    uint64_t slot_count;
    uint64_t survivor_count;
    uint64_t base;
    uint64_t stride;
    uint8_t *snap_ram;
    int      snap_fd;
    uint64_t snap_bytes;

    int      first_fd;
    uint8_t  has_first;
    int      prev_fd;
    uint8_t  has_prev;

    struct fs_segment *seg;
    uint32_t nseg;

    uint64_t value_length;
    uint32_t pid;
    uint8_t  valueType;
};

static struct turboscan_session g_turboscan_sess[TS_MAX_CLIENTS];

static scan_alias_ctx *g_turboscan_alias[TS_MAX_CLIENTS];

void turboscan_alias_free_idx(unsigned char idx) {
    if (idx >= TS_MAX_CLIENTS) return;
    if (g_turboscan_alias[idx]) {
        scan_alias_end(g_turboscan_alias[idx]);
        g_turboscan_alias[idx] = NULL;
    }
}

static scan_alias_ctx *turboscan_alias_acquire(unsigned char idx, uint32_t pid) {
    if (idx >= TS_MAX_CLIENTS) return NULL;
    if (g_turboscan_alias[idx] == NULL)
        g_turboscan_alias[idx] = scan_alias_begin(pid, 0);
    else
        scan_alias_rebind(g_turboscan_alias[idx], pid);
    return g_turboscan_alias[idx];
}

uint64_t g_turboscan_cap_override     = 0;
uint64_t g_turboscan_snap_ram_thresh  = TS_SNAP_RAM_DEFAULT;
char     g_turboscan_spill_dir[64]    = "";
int      g_turboscan_snap_force_fail  = 0;
uint64_t g_turboscan_materialize_max  = TS_MATERIALIZE_COUNT_MAX;

/* Cancel a turbo scan that is running in another connection's thread. The cancel
   handler (0xBDAACC17, on a second connection) stores the pid here; the scan loops
   below poll it read-only (so all parallel workers observe the same request) and
   stop early, falling through to their normal terminator. 0 = no cancel pending.
   START/COUNT clear a stale same-pid value on entry so a fresh scan is never
   pre-cancelled. volatile: written by one thread, read by the scan thread(s). */
volatile int g_turboscan_cancel_pid = 0;

static inline int turbo_cancel_pending(uint32_t pid) {
    int c = g_turboscan_cancel_pid;
    return c != 0 && c == (int)pid;
}

static int fs_pread_all(int fd, void *buf, uint64_t len, uint64_t foff) {
    uint8_t *p = (uint8_t *)buf; uint64_t off = 0;
    while (off < len) {
        ssize_t r = pread(fd, p + off, (size_t)(len - off), (off_t)(foff + off));
        if (r <= 0) return 0;
        off += (uint64_t)r;
    }
    return 1;
}
static int fs_pwrite_all(int fd, const void *buf, uint64_t len, uint64_t foff) {
    const uint8_t *p = (const uint8_t *)buf; uint64_t off = 0;
    while (off < len) {
        ssize_t w = pwrite(fd, p + off, (size_t)(len - off), (off_t)(foff + off));
        if (w <= 0) return 0;
        off += (uint64_t)w;
    }
    return 1;
}

static int snap_store_read(uint8_t *ram, uint64_t ram_bytes, int fd,
                           uint8_t *dst, uint64_t off, uint64_t len) {
    if (off >= ram_bytes) return fs_pread_all(fd, dst, len, off - ram_bytes);
    if (off + len <= ram_bytes) { memcpy(dst, ram + off, len); return 1; }
    uint64_t a = ram_bytes - off;
    memcpy(dst, ram + off, a);
    return fs_pread_all(fd, dst + a, len - a, 0);
}
static int snap_store_write(uint8_t *ram, uint64_t ram_bytes, int fd,
                            const uint8_t *src, uint64_t off, uint64_t len) {
    if (off >= ram_bytes) return fs_pwrite_all(fd, src, len, off - ram_bytes);
    if (off + len <= ram_bytes) { memcpy(ram + off, src, len); return 1; }
    uint64_t a = ram_bytes - off;
    memcpy(ram + off, src, a);
    return fs_pwrite_all(fd, src + a, len - a, 0);
}

static void *fs_mmap_anon(uint64_t n) {

    void *m = (void *)__crt_syscall(477, 0L, (long)n, 3L, 0x1002L, -1L, 0L);
    return (m == (void *)-1 || m == 0) ? NULL : m;
}
static void fs_munmap(void *p, uint64_t n) {
    if (p) __crt_syscall(73, (long)p, (long)n, 0, 0, 0, 0);
}

static void fs_store_path(unsigned char idx, char *out, const char *sfx) {
    const char *dir = g_turboscan_spill_dir[0] ? g_turboscan_spill_dir : "/data";
    int i = 0;
    for (int j = 0; dir[j] && i < 63; j++) out[i++] = dir[j];
    for (int j = 0; sfx[j]; j++) out[i++] = sfx[j];
    out[i++] = (char)('0' + (idx / 10));
    out[i++] = (char)('0' + (idx % 10));
    out[i++] = '.'; out[i++] = 'b'; out[i++] = 'i'; out[i++] = 'n';
    out[i]   = 0;
}
static void fs_snap_path(unsigned char idx, char *out)  { fs_store_path(idx, out, "/ps5dbg_snap_"); }
static void fs_first_path(unsigned char idx, char *out) { fs_store_path(idx, out, "/ps5dbg_first_"); }
static void fs_prev_path(unsigned char idx, char *out)  { fs_store_path(idx, out, "/ps5dbg_prev_"); }

static struct turboscan_session *fs_session_get(unsigned char idx) {
    if (idx >= TS_MAX_CLIENTS) return NULL;
    return &g_turboscan_sess[idx];
}

void turboscan_session_free_idx(unsigned char idx) {
    if (idx >= TS_MAX_CLIENTS) return;
    struct turboscan_session *s = &g_turboscan_sess[idx];
    fs_munmap(s->buf,      s->buf_cap);
    fs_munmap(s->snap_ram, s->snap_bytes);
    fs_munmap(s->bitmap,   s->bitmap_bytes);
    if (s->seg) free(s->seg);
    if (s->mode == TS_MODE_SNAPSHOT) {
        if (s->snap_fd > 0) close(s->snap_fd);
        char path[96];
        fs_snap_path(idx, path);
        unlink(path);
        if (s->first_fd > 0) close(s->first_fd);
        char fpath[96];
        fs_first_path(idx, fpath);
        unlink(fpath);
        if (s->prev_fd > 0) close(s->prev_fd);
        fs_prev_path(idx, fpath);
        unlink(fpath);
    }
    memset(s, 0, sizeof(*s));
}

void turboscan_startup_cleanup(void) {
    char path[96];
    for (unsigned char i = 0; i < TS_MAX_CLIENTS; i++) {
        fs_snap_path(i, path);  unlink(path);
        fs_first_path(i, path); unlink(path);
        fs_prev_path(i, path);  unlink(path);
    }
}

static struct turboscan_session *fs_session_alloc(unsigned char idx, uint32_t pid,
                                                 uint8_t vt, uint64_t vlen) {
    if (idx >= TS_MAX_CLIENTS) return NULL;
    turboscan_session_free_idx(idx);
    uint64_t cap = g_turboscan_cap_override ? g_turboscan_cap_override : TS_RESIDENT_CAP;
    void *m = (void *)__crt_syscall(477, 0L, (long)cap, 3L, 0x1002L, -1L, 0L);
    if (m == (void *)-1 || m == 0) return NULL;
    struct turboscan_session *s = &g_turboscan_sess[idx];
    s->in_use = 1;
    s->mode = TS_MODE_LIST;
    s->buf = m;
    s->buf_cap = cap;
    s->count = 0;
    s->rec_size = 8 + vlen;
    s->value_length = vlen;
    s->pid = pid;
    s->valueType = vt;
    return s;
}

static inline void fs_bm_clear(uint8_t *bm, uint64_t i) { bm[i >> 3] &= (uint8_t)~(1u << (i & 7)); }

static uint64_t fs_next_set(const uint8_t *bm, uint64_t from, uint64_t n) {
    uint64_t i = from;
    while (i < n) {
        if ((i & 63) == 0) {
            while (i + 64 <= n && *(const uint64_t *)(bm + (i >> 3)) == 0) i += 64;
            if (i >= n) break;
        }
        if ((bm[i >> 3] >> (i & 7)) & 1) return i;
        i++;
    }
    return n;
}

static uint64_t fs_slot_addr(const struct turboscan_session *s, uint64_t i) {
    const struct fs_segment *seg = s->seg;
    uint32_t lo = 0, hi = s->nseg;
    while (lo + 1 < hi) {
        uint32_t mid = (lo + hi) >> 1;
        if (seg[mid].slot_start <= i) lo = mid; else hi = mid;
    }
    return seg[lo].addr + (i - seg[lo].slot_start) * s->stride;
}

static int fs_snapshot_create(int fd, unsigned char idx,
                              const struct cmd_proc_turboscan_start_packet *sp,
                              uint64_t value_length, uint64_t step,
                              uint8_t *read_buf, uint64_t chunk_size, uint8_t *pack_buf,
                              const struct cmd_proc_turboscan_snap_segment *in_segs,
                              uint32_t in_nseg, int keep_first, int keep_prev) {
    turboscan_session_free_idx(idx);

    struct fs_segment *seg = (struct fs_segment *)malloc((size_t)in_nseg * sizeof(struct fs_segment));
    if (!seg) {
        struct cmd_proc_turboscan_snap_plan plan = { 0, 0 };
        net_send_all(fd, &plan, sizeof(plan));
        uint64_t sent = 0xFFFFFFFFFFFFFFFFULL; net_send_all(fd, &sent, 8);
        struct cmd_proc_turboscan_snap_summary sum = { 0, 0 };
        net_send_all(fd, &sum, sizeof(sum));
        return 0;
    }

    uint64_t slot_count = 0, total_bytes = 0;
    for (uint32_t g = 0; g < in_nseg; g++) {
        uint64_t len = in_segs[g].length;
        uint64_t ns  = (len >= value_length) ? ((len - value_length) / step + 1) : 0;
        seg[g].addr = in_segs[g].address;
        seg[g].slot_start = slot_count;
        seg[g].nslots = ns;
        slot_count  += ns;
        total_bytes += len;
    }

    uint64_t snap_bytes   = slot_count * value_length;
    uint64_t bitmap_bytes = (slot_count + 7) >> 3;

    int      include_zeros = (sp->flags & TS_SNAPSHOT_INCLUDE_ZEROS) != 0;
    uint64_t survivors = slot_count;

    struct cmd_proc_turboscan_snap_plan plan;
    plan.slot_count = slot_count;
    plan.total_bytes = total_bytes;
    net_send_all(fd, &plan, sizeof(plan));

    uint8_t *bitmap = NULL, *snap_ram = NULL;
    int      snap_fd = -1, use_file = 0, ok = 1, fail = 0;
    uint64_t ram_bytes = 0;
    int      first_fd = -1;
    int      prev_fd  = -1;
    char path[96], fpath[96], ppath[96];
    fs_snap_path(idx, path);
    fs_first_path(idx, fpath);
    fs_prev_path(idx, ppath);

    if (slot_count > 0) {
        if (bitmap_bytes > TS_SNAP_BITMAP_MAX) { ok = 0; }
        if (ok && !(bitmap = (uint8_t *)fs_mmap_anon(bitmap_bytes))) {
            ok = 0;
        }
        if (ok) {
            uint64_t cap = g_turboscan_snap_ram_thresh;
            if (snap_bytes <= cap) {

                snap_ram = (uint8_t *)fs_mmap_anon(snap_bytes);
                if (snap_ram) ram_bytes = snap_bytes;
                else          use_file  = 1;
            } else {
                use_file = 1;
            }
            if (use_file) {

                if (snap_bytes > cap && cap >= value_length && snap_ram == NULL) {
                    uint64_t cache = (cap / value_length) * value_length;
                    snap_ram = (uint8_t *)fs_mmap_anon(cache);
                    if (snap_ram) ram_bytes = cache;
                }
                if (step != value_length && !pack_buf) { ok = 0; }
                else if ((snap_fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0) { ok = 0; }
            }
        }
        if (ok && keep_first) {

            if (step != value_length && !pack_buf) keep_first = 0;
            else if ((first_fd = open(fpath, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0) keep_first = 0;
        }
        if (ok && keep_prev) {

            if (step != value_length && !pack_buf) keep_prev = 0;
            else if ((prev_fd = open(ppath, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0) keep_prev = 0;
        }
        if (ok) memset(bitmap, 0xFF, bitmap_bytes);

        uint64_t done = 0;
        for (uint32_t g = 0; ok && !fail && g < in_nseg; g++) {
            uint64_t seg_base = seg[g].addr, seg_ns = seg[g].nslots, s0 = 0;
            while (ok && !fail && s0 < seg_ns) {
                if (turbo_cancel_pending(sp->pid)) { fail = 1; break; }  /* cancel -> fail path frees the half-built snapshot, replies snapshot_ok=0 */
                uint64_t win_slots = chunk_size / step;
                if (win_slots == 0) win_slots = 1;
                if (s0 + win_slots > seg_ns) win_slots = seg_ns - s0;
                uint64_t gslot  = seg[g].slot_start + s0;
                uint64_t waddr  = seg_base + s0 * step;
                uint64_t wbytes = (win_slots - 1) * step + value_length;
                memset(read_buf, 0, wbytes);
                proc_read_mem(sp->pid, waddr, wbytes, read_buf);

                if (g_turboscan_snap_force_fail) { fail = 1; break; }

                uint64_t pbytes = win_slots * value_length;

                const uint8_t *psrc = NULL;
                if (use_file || keep_first || keep_prev) {
                    if (step == value_length) {
                        psrc = read_buf;
                    } else {
                        for (uint64_t k = 0; k < win_slots; k++)
                            memcpy(pack_buf + k * value_length, read_buf + k * step, value_length);
                        psrc = pack_buf;
                    }
                }
                if (use_file) {
                    if (!snap_store_write(snap_ram, ram_bytes, snap_fd, psrc,
                                          gslot * value_length, pbytes)) { fail = 1; break; }
                } else if (step == value_length) {
                    memcpy(snap_ram + gslot * value_length, read_buf, pbytes);
                } else {
                    for (uint64_t k = 0; k < win_slots; k++)
                        memcpy(snap_ram + (gslot + k) * value_length, read_buf + k * step, value_length);
                }
                if (keep_first &&
                    !fs_pwrite_all(first_fd, psrc, pbytes, gslot * value_length)) { fail = 1; break; }
                if (keep_prev &&
                    !fs_pwrite_all(prev_fd, psrc, pbytes, gslot * value_length)) { fail = 1; break; }
                if (!include_zeros) {
                    for (uint64_t k = 0; k < win_slots; k++) {
                        const uint8_t *v = read_buf + k * step;
                        uint64_t b = 0;
                        while (b < value_length && v[b] == 0) b++;
                        if (b == value_length) { fs_bm_clear(bitmap, gslot + k); survivors--; }
                    }
                }
                s0   += win_slots;
                done += wbytes;
                net_send_all(fd, &done, 8);
            }
        }
    }

    uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
    net_send_all(fd, &sentinel, 8);

    struct cmd_proc_turboscan_snap_summary sum;
    if (!ok || fail) {
        fs_munmap(bitmap, bitmap_bytes);
        fs_munmap(snap_ram, ram_bytes);
        if (snap_fd >= 0) { close(snap_fd); unlink(path); }
        if (first_fd >= 0) { close(first_fd); unlink(fpath); }
        if (prev_fd >= 0) { close(prev_fd); unlink(ppath); }
        free(seg);
        sum.snapshot_ok = 0; sum.survivor_count = 0;
        net_send_all(fd, &sum, sizeof(sum));
        return 0;
    }

    struct turboscan_session *s = &g_turboscan_sess[idx];
    memset(s, 0, sizeof(*s));
    s->in_use = 1; s->mode = TS_MODE_SNAPSHOT;
    s->bitmap = bitmap; s->bitmap_bytes = bitmap_bytes;
    s->slot_count = slot_count; s->survivor_count = survivors;
    s->base = seg[0].addr; s->stride = step;
    s->snap_ram = snap_ram; s->snap_fd = snap_fd;
    s->snap_bytes = ram_bytes;
    s->first_fd = keep_first ? first_fd : -1;
    s->has_first = keep_first ? 1 : 0;
    s->prev_fd = keep_prev ? prev_fd : -1;
    s->has_prev = keep_prev ? 1 : 0;
    s->seg = seg; s->nseg = in_nseg;
    s->value_length = value_length; s->pid = sp->pid; s->valueType = sp->valueType;

    sum.snapshot_ok = 1; sum.survivor_count = survivors;
    net_send_all(fd, &sum, sizeof(sum));
    return 1;
}

/* Read one rescan window via the aliasing engine (full-size windows only) or mdbg (the floor).
   Returns the window base pointer; sets *aliased=1 when it came from the alias engine, in which
   case the caller MUST scan_alias_release(actx) after consuming it. */
static const uint8_t *fs_rescan_window_read(scan_alias_ctx *actx, uint32_t pid,
                                            uint64_t window_start, uint64_t read_size,
                                            uint8_t *mem_buf, int *aliased) {
    *aliased = 0;
    if (actx && read_size >= TS_RESCAN_ALIAS_MIN_WIN) {
        const void *ap = scan_alias_map(actx, window_start, read_size, (uint64_t *)0);
        if (ap) { *aliased = 1; return (const uint8_t *)ap; }
    }
    memset(mem_buf, 0, read_size);
    proc_read_mem(pid, window_start, read_size, mem_buf);
    return mem_buf;
}

static uint64_t fs_snapshot_rescan(int fd, struct turboscan_session *s,
                                   unsigned char cmpType, unsigned char valType,
                                   uint64_t value_length, int turbo_cmp,
                                   const uint8_t *pattern, const uint8_t *mask,
                                   const uint8_t *between_hi, int includes_prev,
                                   uint8_t *mem_buf, uint8_t *bl_buf,
                                   scan_alias_ctx *actx) {
    if (!s->bitmap || s->slot_count == 0) { s->survivor_count = 0; return 0; }
    uint64_t n = s->slot_count, survivors = 0;
    uint64_t rb = s->snap_bytes;

    uint64_t prog_step = n >> 8; if (prog_step == 0) prog_step = 1;
    uint64_t next_prog = prog_step;

    for (uint64_t i = fs_next_set(s->bitmap, 0, n); i < n; ) {
        if (turbo_cancel_pending(s->pid)) break;  /* cancel -> stop narrowing; caller sends the terminator (partial set, see PROTOCOL.md) */
        if (i >= next_prog) { net_send_all(fd, &i, 8); next_prog = i + prog_step; }
        uint64_t window_start = fs_slot_addr(s, i);
        uint64_t covered_end  = window_start + value_length;
        uint64_t last = i;
        for (uint64_t j = fs_next_set(s->bitmap, i + 1, n); j < n; j = fs_next_set(s->bitmap, j + 1, n)) {
            uint64_t na  = fs_slot_addr(s, j);
            uint64_t gap = (na > covered_end) ? (na - covered_end) : 0;
            if (gap > TS_RESCAN_GAP_MAX) break;
            uint64_t ne = na + value_length;
            if (ne - window_start > TS_RESCAN_WIN_CAP) break;
            covered_end = ne; last = j;
        }
        uint64_t read_size = covered_end - window_start;
        int win_aliased;
        const uint8_t *win = fs_rescan_window_read(actx, s->pid, window_start, read_size,
                                                   mem_buf, &win_aliased);

        uint64_t bl_off = i * value_length, bl_len = (last - i + 1) * value_length;
        uint8_t *bl;
        int buffered = (bl_off + bl_len > rb);
        if (buffered) { snap_store_read(s->snap_ram, rb, s->snap_fd, bl_buf, bl_off, bl_len); bl = bl_buf; }
        else          { bl = s->snap_ram + bl_off; }

        if (s->has_prev) fs_pwrite_all(s->prev_fd, bl, bl_len, bl_off);

        int dirty = 0;
        for (uint64_t k = i; k <= last; k = fs_next_set(s->bitmap, k + 1, n)) {
            uint64_t addr = fs_slot_addr(s, k);
            const uint8_t *mem_ptr  = win + (addr - window_start);
            uint8_t       *base_ptr = bl + (k - i) * value_length;
            const uint8_t *prev_ptr = includes_prev ? base_ptr : between_hi;
            int matched = turbo_cmp
                ? scan_point_compare(cmpType, valType, mem_ptr, pattern, prev_ptr)
                : (int)proc_scan_compareValues(cmpType, valType, value_length, pattern, mem_ptr, prev_ptr, mask);
            if (matched) { memcpy(base_ptr, mem_ptr, value_length); dirty = 1; survivors++; }
            else         { fs_bm_clear(s->bitmap, k); }
        }
        if (win_aliased) scan_alias_release(actx);
        if (buffered && dirty) snap_store_write(s->snap_ram, rb, s->snap_fd, bl, bl_off, bl_len);

        i = fs_next_set(s->bitmap, last + 1, n);
    }
    s->survivor_count = survivors;
    return survivors;
}

static uint32_t fs_snapshot_get(int fd, struct turboscan_session *s,
                                uint32_t start, uint32_t count,
                                uint8_t *out_buf, uint64_t out_cap) {
    uint64_t value_length = s->value_length, n = s->slot_count;
    int has_first = s->has_first;
    uint32_t actual = 0;
    if (start < s->survivor_count) {
        uint64_t avail = s->survivor_count - start;
        actual = (count < avail) ? count : (uint32_t)avail;
    }

    uint32_t hdr = actual | (has_first ? 0x80000000u : 0u);
    net_send_all(fd, &hdr, 4);
    if (actual == 0 || !s->bitmap) return 0;

    uint64_t rb = s->snap_bytes;
    uint64_t ent = 8 + value_length * (has_first ? 3 : 2), out_len = 0, seen = 0, emitted = 0;
    for (uint64_t i = fs_next_set(s->bitmap, 0, n); i < n && emitted < actual;
                  i = fs_next_set(s->bitmap, i + 1, n)) {
        if (seen < start) { seen++; continue; }
        uint64_t addr = fs_slot_addr(s, i);
        if (out_len + ent > out_cap) { net_send_all(fd, out_buf, (int)out_len); out_len = 0; }
        uint8_t *o = out_buf + out_len;
        memcpy(o, &addr, 8);

        snap_store_read(s->snap_ram, rb, s->snap_fd, o + 8, i * value_length, value_length);
        if (s->has_prev)
            fs_pread_all(s->prev_fd, o + 8 + value_length, value_length, i * value_length);
        else
            memcpy(o + 8 + value_length, o + 8, value_length);
        if (has_first)
            fs_pread_all(s->first_fd, o + 8 + 2 * value_length, value_length, i * value_length);
        out_len += ent; emitted++; seen++;
    }
    if (out_len) net_send_all(fd, out_buf, (int)out_len);
    return (uint32_t)emitted;
}

static int fs_snapshot_materialize(unsigned char idx, struct turboscan_session *s) {
    uint64_t vlen = s->value_length;
    int has_first = s->has_first, has_prev = s->has_prev;

    uint64_t prev_off  = 8 + vlen;
    uint64_t first_off = 8 + vlen + (has_prev ? vlen : 0);
    uint64_t rec_size  = 8 + vlen * (1 + (has_prev ? 1 : 0) + (has_first ? 1 : 0));
    uint64_t records = s->survivor_count;
    if (records == 0 || rec_size == 0 || records * rec_size > TS_RESIDENT_CAP) return 0;

    uint64_t bytes = records * rec_size;
    void *buf = fs_mmap_anon(bytes);
    if (!buf) return 0;

    uint64_t rb = s->snap_bytes;
    uint8_t *recs = (uint8_t *)buf;
    uint64_t n = s->slot_count, out = 0;
    uint8_t  bl_small[8];

    for (uint64_t i = fs_next_set(s->bitmap, 0, n); i < n && out < records;
                  i = fs_next_set(s->bitmap, i + 1, n)) {
        const uint8_t *val;
        uint64_t voff = i * vlen;
        if (voff >= rb) {
            if (!fs_pread_all(s->snap_fd, bl_small, vlen, voff - rb)) { fs_munmap(buf, bytes); return 0; }
            val = bl_small;
        } else {
            val = s->snap_ram + voff;
        }
        uint64_t addr = fs_slot_addr(s, i);
        uint8_t *rec = recs + out * rec_size;
        memcpy(rec, &addr, 8);
        memcpy(rec + 8, val, vlen);
        if (has_prev) {
            if (!fs_pread_all(s->prev_fd, rec + prev_off, vlen, voff)) { fs_munmap(buf, bytes); return 0; }
        }
        if (has_first) {
            if (!fs_pread_all(s->first_fd, rec + first_off, vlen, voff)) { fs_munmap(buf, bytes); return 0; }
        }
        out++;
    }

    fs_munmap(s->snap_ram, s->snap_bytes);
    fs_munmap(s->bitmap,   s->bitmap_bytes);
    if (s->snap_fd > 0) close(s->snap_fd);
    if (s->first_fd > 0) close(s->first_fd);
    if (s->prev_fd > 0) close(s->prev_fd);
    if (s->seg) free(s->seg);
    { char path[96]; fs_snap_path(idx, path); unlink(path);
      if (has_first) { fs_first_path(idx, path); unlink(path); }
      if (has_prev)  { fs_prev_path(idx, path);  unlink(path); } }

    uint8_t  vt = s->valueType; uint32_t pid = s->pid;
    memset(s, 0, sizeof(*s));
    s->in_use = 1; s->mode = TS_MODE_LIST;
    s->buf = buf; s->buf_cap = bytes; s->count = out; s->rec_size = rec_size;
    s->value_length = vlen; s->pid = pid; s->valueType = vt;
    s->has_first = has_first; s->first_fd = -1;
    s->has_prev = has_prev; s->prev_fd = -1;
    return 1;
}

static int turboscan_scan_pass_range(int fd,
                              const struct cmd_proc_turboscan_start_packet *sp,
                              uint64_t scan_addr, uint64_t scan_len,
                              uint64_t value_length, uint64_t step,
                              const uint8_t *pattern, const uint8_t *mask,
                              const void *prev_for_between, int simd_ok,
                              uint8_t *read_buf, uint64_t chunk_size,
                              uint8_t *result_buf, uint32_t *simd_off, uint64_t simd_max,
                              struct turboscan_session *sess, scan_alias_ctx *actx) {
    uint64_t addr = scan_addr;
    uint64_t remaining = scan_len;
    uint64_t result_len = 0;
    uint64_t flush_thresh = 0x3FFE8ULL - value_length;

    while (remaining > 0) {
        if (turbo_cancel_pending(sp->pid)) break;  /* cancel -> stop; flush partial results + normal terminator (also honoured by parallel workers) */
        uint64_t to_read = (remaining > chunk_size) ? chunk_size : remaining;

        const uint8_t *src;
        const void *aptr = actx ? scan_alias_map(actx, addr, to_read, (uint64_t *)0)
                                : (const void *)0;
        if (aptr) {
            src = (const uint8_t *)aptr;
        } else {
            memset(read_buf, 0, to_read);
            proc_read_mem(sp->pid, addr, to_read, read_buf);
            src = read_buf;
        }

        if (simd_ok) {
            size_t nm = scan_simd_find_exact(sp->valueType, src, (size_t)to_read,
                                             pattern, (uint32_t)value_length,
                                             simd_off, (size_t)simd_max);
            for (size_t k = 0; k < nm; k++) {
                uint32_t coff = simd_off[k];
                if (sess) {
                    if ((sess->count + 1) * sess->rec_size > sess->buf_cap) {
                        if (aptr) scan_alias_release(actx);
                        return 0;
                    }
                    uint8_t *rec = (uint8_t *)sess->buf + sess->count * sess->rec_size;
                    uint64_t a = addr + coff;
                    memcpy(rec, &a, 8);
                    memcpy(rec + 8, &src[coff], value_length);
                    sess->count++;
                } else {
                    if (result_len > flush_thresh) {
                        *(uint64_t *)result_buf = result_len;
                        net_send_all(fd, result_buf, (int)(result_len + 8));
                        result_len = 0;
                    }
                    uint32_t offset = (uint32_t)((addr + coff) - sp->address);
                    memcpy(result_buf + 8 + result_len,     &offset,    4);
                    memcpy(result_buf + 8 + result_len + 4, &src[coff], value_length);
                    result_len += 4 + value_length;
                }
            }
        } else {
            uint64_t limit = (to_read >= value_length) ? to_read - value_length : 0;
            for (uint64_t j = 0; j <= limit; j += step) {
                if (proc_scan_compareValues(sp->compareType, sp->valueType, value_length,
                                            pattern, &src[j], prev_for_between, mask)) {
                    if (sess) {
                        if ((sess->count + 1) * sess->rec_size > sess->buf_cap) {
                            if (aptr) scan_alias_release(actx);
                            return 0;
                        }
                        uint8_t *rec = (uint8_t *)sess->buf + sess->count * sess->rec_size;
                        uint64_t a = addr + j;
                        memcpy(rec, &a, 8);
                        memcpy(rec + 8, &src[j], value_length);
                        sess->count++;
                    } else {
                        if (result_len > flush_thresh) {
                            *(uint64_t *)result_buf = result_len;
                            net_send_all(fd, result_buf, (int)(result_len + 8));
                            result_len = 0;
                        }
                        uint32_t offset = (uint32_t)((addr + j) - sp->address);
                        memcpy(result_buf + 8 + result_len,     &offset, 4);
                        memcpy(result_buf + 8 + result_len + 4, &src[j], value_length);
                        result_len += 4 + value_length;
                    }
                }
            }
        }

        if (aptr) scan_alias_release(actx);

        uint64_t advance = to_read + step - value_length;
        if (advance == 0 || advance > to_read) advance = to_read;
        addr += advance;
        remaining = (remaining > advance) ? remaining - advance : 0;
    }

    if (!sess && result_len) {
        *(uint64_t *)result_buf = result_len;
        net_send_all(fd, result_buf, (int)(result_len + 8));
    }
    return 1;
}

static int turboscan_scan_pass(int fd,
                              const struct cmd_proc_turboscan_start_packet *sp,
                              uint64_t value_length, uint64_t step,
                              const uint8_t *pattern, const uint8_t *mask,
                              const void *prev_for_between, int simd_ok,
                              uint8_t *read_buf, uint64_t chunk_size,
                              uint8_t *result_buf, uint32_t *simd_off, uint64_t simd_max,
                              struct turboscan_session *sess, scan_alias_ctx *actx) {
    return turboscan_scan_pass_range(fd, sp, sp->address, sp->length,
                                    value_length, step, pattern, mask,
                                    prev_for_between, simd_ok, read_buf, chunk_size,
                                    result_buf, simd_off, simd_max, sess, actx);
}

#define TS_PARALLEL_WORKERS 2
#define TS_PAR_MAX_WORKERS  2
#define TS_PAR_RESULT_CAP  (8ULL << 20)
#define TS_PAR_ARENA       (16ULL << 20)

struct fs_par_worker {
    const struct cmd_proc_turboscan_start_packet *sp;
    uint64_t scan_addr, scan_len, value_length, step, chunk_size, simd_max;
    const uint8_t *pattern, *mask;
    const void *prev_for_between;
    int simd_ok;
    uint8_t *read_buf;
    uint32_t *simd_off;
    scan_alias_ctx *actx;
    struct turboscan_session sess;
    int ok;
};

static void *fs_par_thread(void *arg) {
    struct fs_par_worker *w = (struct fs_par_worker *)arg;

    w->ok = turboscan_scan_pass_range(-1, w->sp, w->scan_addr, w->scan_len,
                                     w->value_length, w->step, w->pattern, w->mask,
                                     w->prev_for_between, w->simd_ok, w->read_buf,
                                     w->chunk_size, (uint8_t *)0, w->simd_off, w->simd_max,
                                     &w->sess, w->actx);
    return (void *)0;
}

static int turboscan_parallel_stream(int fd,
        const struct cmd_proc_turboscan_start_packet *sp,
        uint64_t value_length, uint64_t step,
        const uint8_t *pattern, const uint8_t *mask,
        const void *prev_for_between, int simd_ok,
        uint64_t chunk_size, uint64_t simd_max, scan_alias_ctx *actx) {

    if (!(sp->flags & TS_PARALLEL_COMPARE)) return 0;
    if (!simd_ok || !actx) return 0;
    if (sp->length < value_length * 2) return 0;
    uint32_t nw = TS_PARALLEL_WORKERS;

    uint64_t span = (sp->length + nw - 1) / nw;
    span = ((span + value_length - 1) / value_length) * value_length;
    if (span == 0) return 0;
    nw = (uint32_t)((sp->length + span - 1) / span);
    if (nw <= 1 || nw > TS_PAR_MAX_WORKERS) return 0;

    { uint64_t pp = 0, ps = 0, pe = 0; int pl = 0; proc_ptwalk_probe(sp->pid, sp->address, &pp, &pl, &ps, &pe); }

    struct fs_par_worker *w = (struct fs_par_worker *)malloc((size_t)nw * sizeof(*w));
    if (!w) return 0;
    memset(w, 0, (size_t)nw * sizeof(*w));
    ScePthread tids[TS_PAR_MAX_WORKERS];
    int spawned[TS_PAR_MAX_WORKERS];
    uint32_t rec_size = (uint32_t)(8 + value_length);
    int alloc_ok = 1;

    for (uint32_t i = 0; i < nw; i++) {
        uint64_t s_off = (uint64_t)i * span;
        uint64_t s_len = (s_off + span <= sp->length) ? span : (sp->length - s_off);
        w[i].sp = sp; w[i].scan_addr = sp->address + s_off; w[i].scan_len = s_len;
        w[i].value_length = value_length; w[i].step = step;
        w[i].chunk_size = chunk_size; w[i].simd_max = simd_max;
        w[i].pattern = pattern; w[i].mask = mask; w[i].prev_for_between = prev_for_between;
        w[i].simd_ok = simd_ok;
        w[i].read_buf = (uint8_t *)malloc(chunk_size);
        w[i].simd_off = (uint32_t *)malloc((size_t)simd_max * 4);
        w[i].sess.buf = (uint8_t *)malloc(TS_PAR_RESULT_CAP);
        w[i].sess.buf_cap = TS_PAR_RESULT_CAP; w[i].sess.count = 0; w[i].sess.rec_size = rec_size;
        w[i].sess.value_length = value_length;
        w[i].actx = scan_alias_begin(sp->pid, TS_PAR_ARENA);
        if (!w[i].read_buf || !w[i].simd_off || !w[i].sess.buf || !w[i].actx) alloc_ok = 0;
        spawned[i] = 0;
    }

    int handled = 0;
    if (alloc_ok) {
        for (uint32_t i = 1; i < nw; i++)
            if (scePthreadCreate(&tids[i], NULL, fs_par_thread, &w[i], "fsscan") == 0) spawned[i] = 1;
        fs_par_thread(&w[0]);
        for (uint32_t i = 1; i < nw; i++) {
            if (spawned[i]) scePthreadJoin(tids[i], NULL);
            else fs_par_thread(&w[i]);
        }

        int all_ok = 1;
        for (uint32_t i = 0; i < nw; i++) if (!w[i].ok) all_ok = 0;

        if (all_ok) {
            uint8_t *blk = (uint8_t *)malloc(0x40000);
            if (blk) {
                uint64_t blen = 0;
                uint64_t thresh = 0x3FFE8ULL - value_length;
                for (uint32_t i = 0; i < nw; i++) {
                    for (uint64_t r = 0; r < w[i].sess.count; r++) {
                        uint8_t *rec = (uint8_t *)w[i].sess.buf + r * rec_size;
                        uint64_t a; memcpy(&a, rec, 8);
                        uint32_t off = (uint32_t)(a - sp->address);
                        if (blen > thresh) {
                            *(uint64_t *)blk = blen;
                            net_send_all(fd, blk, (int)(blen + 8));
                            blen = 0;
                        }
                        memcpy(blk + 8 + blen,     &off,    4);
                        memcpy(blk + 8 + blen + 4, rec + 8, value_length);
                        blen += 4 + value_length;
                    }
                }
                if (blen) { *(uint64_t *)blk = blen; net_send_all(fd, blk, (int)(blen + 8)); }
                free(blk);
                handled = 1;
            }
        }
    }

    for (uint32_t i = 0; i < nw; i++) {
        if (w[i].actx) scan_alias_end(w[i].actx);
        if (w[i].read_buf) free(w[i].read_buf);
        if (w[i].simd_off) free(w[i].simd_off);
        if (w[i].sess.buf) free(w[i].sess.buf);
    }
    free(w);
    return handled;
}

int proc_turboscan_config_handle(int fd, struct cmd_packet *packet) {
    if (!(g_proc_auth_state & 2)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    struct cmd_proc_turboscan_config_packet *cp =
        (struct cmd_proc_turboscan_config_packet *)packet->data;
    if (!cp || packet->datalen < sizeof(*cp)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    uint32_t plen = cp->spill_path_len;
    if (plen > 63 || (uint64_t)sizeof(*cp) + plen > packet->datalen) {
        net_send_int32(fd, CMD_DATA_NULL); return 1;
    }

    g_turboscan_snap_ram_thresh = cp->ram_thresh_mb
        ? ((uint64_t)cp->ram_thresh_mb << 20) : TS_SNAP_RAM_DEFAULT;

    const uint8_t *p = (const uint8_t *)packet->data + sizeof(*cp);
    uint32_t n = 0;
    for (; n < plen; n++) g_turboscan_spill_dir[n] = (char)p[n];
    g_turboscan_spill_dir[n] = 0;

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

/* Turbo Scan CANCEL (raw literal 0xBDAACC17). Sent from a SECOND connection (the one
   running the scan is busy streaming, so it cannot receive a command). Arms a pid-scoped
   cancel flag that the in-flight START/COUNT scan loops poll; they stop early and emit their
   normal terminator. The cancelled session is left indeterminate (partial), except a cancelled
   snapshot CREATE cleanly reports snapshot_ok=0 - see PROTOCOL.md. Requires auth bit 1. */
int proc_turboscan_cancel_handle(int fd, struct cmd_packet *packet) {
    if (!(g_proc_auth_state & 2)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    struct ts_cancel_req { uint32_t pid; } __attribute__((packed));
    struct ts_cancel_req *r = (struct ts_cancel_req *)packet->data;
    if (!r || packet->datalen < sizeof(*r) || r->pid == 0) {
        net_send_int32(fd, CMD_DATA_NULL); return 1;
    }
    g_turboscan_cancel_pid = (int)r->pid;
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int proc_turboscan_caps_handle(int fd, struct cmd_packet *packet) {
    (void)packet;
    struct cmd_proc_turboscan_caps_response resp;
    memset(&resp, 0, sizeof(resp));
    resp.version     = 1;
    resp.engines     = TSE_SIMD_COMPARE | TSE_SERVER_RESIDENT | TSE_SNAPSHOT
                     | TSE_SNAPSHOT_SEGMENTS | TSE_SNAPSHOT_CONFIG | TSE_SNAPSHOT_FIRST
                     | TSE_SNAPSHOT_PREVIOUS | TSE_ALIASING | TSE_PARALLEL_COMPARE
                     | TSE_RESCAN_ALIASING;
    resp.max_threads = TS_WORKER_THREADS;
    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, &resp, sizeof(resp));
    return 0;
}

#define TS_REGIONS_DEFAULT_MAX 1024u
#define TS_REGIONS_HARD_MAX    8192u
#define TS_REGIONS_PROBE_DEF   0x10000u
#define TS_REGIONS_PROBE_MAX   0x100000u

int proc_turboscan_regions_handle(int fd, struct cmd_packet *packet) {
    if (!(g_proc_auth_state & 2)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    struct cmd_proc_turboscan_regions_packet *rp =
        (struct cmd_proc_turboscan_regions_packet *)packet->data;
    if (!rp || packet->datalen < sizeof(*rp)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    uint32_t pid = rp->pid;
    uint32_t cap = rp->max ? rp->max : TS_REGIONS_DEFAULT_MAX;
    if (cap > TS_REGIONS_HARD_MAX) cap = TS_REGIONS_HARD_MAX;
    uint32_t probe_bytes = rp->probe_bytes ? rp->probe_bytes : TS_REGIONS_PROBE_DEF;
    if (probe_bytes > TS_REGIONS_PROBE_MAX) probe_bytes = TS_REGIONS_PROBE_MAX;

    void *maps = NULL; int count = 0;
    if (sys_proc_vm_map(pid, &maps, &count) != 0 || count <= 0) {
        net_send_int32(fd, CMD_DATA_NULL); return 1;
    }
    struct proc_vm_map_entry *e = (struct proc_vm_map_entry *)maps;

    struct cmd_proc_turboscan_region_info *out =
        (struct cmd_proc_turboscan_region_info *)malloc((size_t)cap * sizeof(*out));
    uint8_t *probe = (uint8_t *)malloc(probe_bytes);
    if (!out || !probe) {
        free(out); free(probe); free(maps);
        net_send_int32(fd, CMD_DATA_NULL); return 1;
    }

    uint32_t n = 0;
    for (int i = 0; i < count && n < cap; i++) {
        if (!(e[i].prot & 1)) continue;
        uint64_t st = e[i].start, en = e[i].end;
        if (en <= st) continue;

        uint32_t rflags = 0;
        uint64_t pte = 0, ph = 0, pg = 0; int lv = -1;
        if (proc_ptwalk_probe(pid, st, &ph, &lv, &pg, &pte) == 0 && ((pte >> 4) & 1))
            rflags |= 1u;

        uint64_t pb = (en - st) < probe_bytes ? (en - st) : probe_bytes;
        double t0 = sf_now();
        proc_read_mem(pid, st, pb, probe);
        double t1 = sf_now();
        double dt = t1 - t0;
        double mbps = dt > 0 ? ((double)pb / 1e6) / dt : 0.0;
        if (mbps < 0.0) mbps = 0.0;
        if (mbps > 4294967295.0) mbps = 4294967295.0;

        out[n].start    = st;
        out[n].end      = en;
        out[n].prot     = e[i].prot;
        out[n].flags    = rflags;
        out[n].mbps     = (uint32_t)mbps;
        out[n].reserved = 0;
        n++;
    }

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, &n, 4);
    if (n) net_send_all(fd, out, (int)((size_t)n * sizeof(*out)));
    net_send_int32(fd, CMD_SUCCESS);

    free(out); free(probe); free(maps);
    return 0;
}

int proc_turboscan_start_handle(int fd, struct cmd_packet *packet, unsigned char client_idx) {
    if (!(g_proc_auth_state & 2)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    struct cmd_proc_turboscan_start_packet *sp =
        (struct cmd_proc_turboscan_start_packet *)packet->data;
    if (!sp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    if (g_turboscan_cancel_pid == (int)sp->pid) g_turboscan_cancel_pid = 0;  /* discard any stale cancel for this pid before we start */
    int want_snapshot = (sp->flags & TS_SNAPSHOT) != 0;
    if (sp->compareType > 12 || (sp->lenData == 0 && !want_snapshot)) {
        net_send_int32(fd, CMD_DATA_NULL); return 1;
    }

    int needs_scan_value = ((1u << sp->compareType) & 0x114Fu) != 0;
    int is_between  = (sp->compareType == 4);
    int is_arrbytes = (sp->valueType == 10);
    if (is_between) needs_scan_value = 1;

    uint64_t value_length = proc_scan_getSizeOfValueType(sp->valueType);
    if (value_length == 0) value_length = sp->lenData;
    if (value_length == 0) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    uint8_t *pattern = NULL;
    if (needs_scan_value && sp->lenData) {
        pattern = (uint8_t *)net_alloc_buffer(sp->lenData);
        if (!pattern) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    }

    net_send_int32(fd, CMD_SUCCESS);
    if (pattern) net_recv_all(fd, pattern, (int)sp->lenData, 1);

    uint8_t *mask = NULL;
    if (is_arrbytes) {
        mask = (uint8_t *)net_alloc_buffer((uint32_t)value_length);
        if (!mask) { if (pattern) free(pattern); net_send_int32(fd, CMD_DATA_NULL); return 1; }
        net_recv_all(fd, mask, (int)value_length, 1);
    }

    uint64_t step = sp->alignment ? sp->alignment : value_length;
    uint64_t chunk_size = 0x100000ULL;
    if (chunk_size % value_length != 0) chunk_size = (chunk_size / value_length) * value_length;

    uint8_t *read_buf   = (uint8_t *)net_alloc_buffer(chunk_size);
    uint8_t *result_buf = (uint8_t *)net_alloc_buffer(0x40000);

    int simd_ok = (sp->compareType == 0) && !is_arrbytes && (step == value_length) && pattern != NULL;
    uint32_t *simd_off = NULL;
    uint64_t  simd_max = 0;
    if (simd_ok) {
        simd_max = chunk_size / value_length;
        simd_off = (uint32_t *)net_alloc_buffer((uint32_t)(simd_max * 4));
        if (!simd_off) simd_ok = 0;
    }

    if (!read_buf || !result_buf) {
        if (read_buf) free(read_buf);
        if (result_buf) free(result_buf);
        if (simd_off) free(simd_off);
        if (pattern) free(pattern);
        if (mask) free(mask);
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }

    net_send_int32(fd, CMD_SUCCESS);

    if (want_snapshot) {
        struct cmd_proc_turboscan_snap_segment *segs = NULL;
        uint32_t nseg = 0;
        struct cmd_proc_turboscan_snap_segment one;
        int seg_ok = 1;

        if (sp->flags & TS_SNAPSHOT_SEGMENTS) {
            net_recv_all(fd, &nseg, 4, 1);
            if (nseg >= 1 && nseg <= TS_SNAP_MAX_SEGS) {
                segs = (struct cmd_proc_turboscan_snap_segment *)
                       malloc((size_t)nseg * sizeof(struct cmd_proc_turboscan_snap_segment));
                if (segs) {
                    net_recv_all(fd, segs, (int)(nseg * sizeof(struct cmd_proc_turboscan_snap_segment)), 1);
                } else {
                    uint64_t togo = (uint64_t)nseg * sizeof(struct cmd_proc_turboscan_snap_segment);
                    while (togo) {
                        uint64_t c = (togo < chunk_size) ? togo : chunk_size;
                        net_recv_all(fd, read_buf, (int)c, 1);
                        togo -= c;
                    }
                    seg_ok = 0;
                }
            } else {
                seg_ok = 0;
            }
        } else {
            one.address = sp->address;
            one.length  = sp->length;
            segs = &one;
            nseg = 1;
        }

        if (!seg_ok || value_length > 8 || value_length == 0) {
            struct cmd_proc_turboscan_snap_plan plan = { 0, 0 };
            net_send_all(fd, &plan, sizeof(plan));
            uint64_t sent = 0xFFFFFFFFFFFFFFFFULL; net_send_all(fd, &sent, 8);
            struct cmd_proc_turboscan_snap_summary sum = { 0, 0 };
            net_send_all(fd, &sum, sizeof(sum));
        } else {

            int keep_first = (sp->flags & TS_SNAPSHOT_KEEP_FIRST) != 0;
            int keep_prev  = (sp->flags & TS_SNAPSHOT_KEEP_PREVIOUS) != 0;
            uint64_t io_chunk = TS_SNAP_IO_CHUNK;
            if (io_chunk % value_length) io_chunk = (io_chunk / value_length) * value_length;
            uint8_t *rbuf = (uint8_t *)fs_mmap_anon(io_chunk);
            uint8_t *pbuf = (uint8_t *)fs_mmap_anon(io_chunk);
            if (rbuf && pbuf) {
                fs_snapshot_create(fd, client_idx, sp, value_length, step,
                                   rbuf, io_chunk, pbuf, segs, nseg, keep_first, keep_prev);
            } else {
                uint8_t *pack_buf = (uint8_t *)net_alloc_buffer(chunk_size);
                fs_snapshot_create(fd, client_idx, sp, value_length, step,
                                   read_buf, chunk_size, pack_buf, segs, nseg, keep_first, keep_prev);
                if (pack_buf) free(pack_buf);
            }
            if (rbuf) fs_munmap(rbuf, io_chunk);
            if (pbuf) fs_munmap(pbuf, io_chunk);
        }
        if (segs && segs != &one) free(segs);
        free(read_buf); free(result_buf);
        if (simd_off) free(simd_off);
        if (pattern) free(pattern);
        if (mask) free(mask);
        net_send_int32(fd, CMD_SUCCESS);
        return 0;
    }

    const void *prev_for_between = is_between ? (pattern + value_length) : NULL;

    scan_alias_ctx *actx = (sp->flags & TS_USE_ALIASING)
                         ? turboscan_alias_acquire(client_idx, sp->pid) : NULL;

    int resident = (sp->flags & TS_SERVER_RESIDENT) != 0;

    int use_segments = resident && (sp->flags & TS_SNAPSHOT_SEGMENTS) != 0;
    struct cmd_proc_turboscan_snap_segment *segs = NULL;
    uint32_t nseg = 0;
    int seg_ok = 1;
    if (use_segments) {
        net_recv_all(fd, &nseg, 4, 1);
        if (nseg >= 1 && nseg <= TS_SNAP_MAX_SEGS) {
            segs = (struct cmd_proc_turboscan_snap_segment *)
                   malloc((size_t)nseg * sizeof(struct cmd_proc_turboscan_snap_segment));
            if (segs) {
                net_recv_all(fd, segs, (int)(nseg * sizeof(struct cmd_proc_turboscan_snap_segment)), 1);
            } else {
                uint64_t togo = (uint64_t)nseg * sizeof(struct cmd_proc_turboscan_snap_segment);
                while (togo) {
                    uint64_t c = (togo < chunk_size) ? togo : chunk_size;
                    net_recv_all(fd, read_buf, (int)c, 1);
                    togo -= c;
                }
                seg_ok = 0;
            }
        } else {
            seg_ok = 0;
        }
    }

    if (resident) {
        struct turboscan_session *s = (value_length <= 0x1000 && seg_ok)
            ? fs_session_alloc(client_idx, sp->pid, sp->valueType, value_length) : NULL;
        int stored = 0;
        if (s) {
            if (use_segments) {

                stored = 1;
                for (uint32_t g = 0; g < nseg; g++) {
                    if (!turboscan_scan_pass_range(fd, sp, segs[g].address, segs[g].length,
                                                  value_length, step, pattern, mask,
                                                  prev_for_between, simd_ok, read_buf, chunk_size,
                                                  result_buf, simd_off, simd_max, s, actx)) {
                        stored = 0;
                        break;
                    }
                }
            } else {
                stored = turboscan_scan_pass(fd, sp, value_length, step, pattern, mask,
                                            prev_for_between, simd_ok, read_buf, chunk_size,
                                            result_buf, simd_off, simd_max, s, actx);
            }
        }
        if (stored) {
            struct cmd_proc_turboscan_resident_summary sum;
            sum.resident_stored = 1;
            sum.count = s->count;
            net_send_all(fd, &sum, sizeof(sum));
            if (segs) free(segs);
            free(read_buf); free(result_buf);
            if (simd_off) free(simd_off);
            if (pattern) free(pattern);
            if (mask) free(mask);
            scan_alias_release(actx);
            net_send_int32(fd, CMD_SUCCESS);
            return 0;
        }
        turboscan_session_free_idx(client_idx);
        struct cmd_proc_turboscan_resident_summary sum;
        sum.resident_stored = 0;
        sum.count = 0;
        net_send_all(fd, &sum, sizeof(sum));

        if (use_segments) {

            uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
            net_send_all(fd, &sentinel, 8);
            if (segs) free(segs);
            free(read_buf); free(result_buf);
            if (simd_off) free(simd_off);
            if (pattern) free(pattern);
            if (mask) free(mask);
            scan_alias_release(actx);
            net_send_int32(fd, CMD_SUCCESS);
            return 0;
        }
    }

    if (segs) free(segs);

    if (!turboscan_parallel_stream(fd, sp, value_length, step, pattern, mask,
                                  prev_for_between, simd_ok, chunk_size, simd_max, actx)) {
        turboscan_scan_pass(fd, sp, value_length, step, pattern, mask,
                           prev_for_between, simd_ok, read_buf, chunk_size,
                           result_buf, simd_off, simd_max, NULL, actx);
    }

    uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
    net_send_all(fd, &sentinel, 8);

    free(read_buf);
    free(result_buf);
    if (simd_off) free(simd_off);
    if (pattern) free(pattern);
    if (mask) free(mask);
    scan_alias_release(actx);
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int proc_turboscan_count_handle(int fd, struct cmd_packet *packet, unsigned char client_idx) {
    if (!(g_proc_auth_state & 2)) {
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }

    struct cmd_proc_turboscan_count_packet *cp =
        (struct cmd_proc_turboscan_count_packet *)packet->data;
    if (!cp) {
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }
    if (cp->compareType > 12) {
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }
    if (g_turboscan_cancel_pid == (int)cp->pid) g_turboscan_cancel_pid = 0;  /* discard any stale cancel for this pid before we start */
    int resident = (cp->flags & TS_SERVER_RESIDENT) != 0;

    int needs_value_flag    = g_cmptype_needs_value   [cp->compareType] != 0;
    int needs_extra_flag    = g_cmptype_needs_extra   [cp->compareType] != 0;
    int needs_previous_flag = g_cmptype_needs_previous[cp->compareType] != 0;
    int needs_scan_value    = needs_value_flag || needs_extra_flag;
    int is_arrbytes         = (cp->valueType == 10);
    int is_between          = (cp->compareType == 4);

    uint64_t value_length = proc_scan_getSizeOfValueType(cp->valueType);
    if (value_length == 0) value_length = cp->lenData;
    if (value_length == 0 || value_length > 0x1000) {
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }

    int turbo_cmp = scan_point_turbo_supported(cp->compareType, cp->valueType);

    uint8_t *pattern = NULL;
    uint8_t *mask    = NULL;
    if (needs_scan_value && cp->lenData) {
        pattern = (uint8_t *)net_alloc_buffer(cp->lenData);
        if (!pattern) {
            net_send_int32(fd, CMD_DATA_NULL);
            return 1;
        }
    }
    if (is_arrbytes) {
        mask = (uint8_t *)net_alloc_buffer((uint32_t)value_length);
        if (!mask) {
            if (pattern) free(pattern);
            net_send_int32(fd, CMD_DATA_NULL);
            return 1;
        }
    }

    uint8_t *chunk_buf  = (uint8_t *)net_alloc_buffer(0x40000);
    uint8_t *result_buf = (uint8_t *)net_alloc_buffer(0x40000);
    uint8_t *mem_buf    = (uint8_t *)net_alloc_buffer(0x100000);
    if (!chunk_buf || !result_buf || !mem_buf) {
        if (chunk_buf)  free(chunk_buf);
        if (result_buf) free(result_buf);
        if (mem_buf)    free(mem_buf);
        if (pattern)    free(pattern);
        if (mask)       free(mask);
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }

    net_send_int32(fd, CMD_SUCCESS);
    if (pattern) net_recv_all(fd, pattern, (int)cp->lenData, 1);
    if (mask)    net_recv_all(fd, mask,    (int)value_length, 1);

    const uint8_t *between_hi = (is_between && pattern && cp->lenData >= 2 * value_length)
                                ? (pattern + value_length) : NULL;

    int      includes_prev = needs_previous_flag;
    uint64_t entry_size    = includes_prev ? (4 + value_length) : 4;
    uint64_t flush_thresh  = 0x3FFE8ULL - 2 * value_length;

    if (resident) {
        struct turboscan_session *s = fs_session_get(client_idx);

        if (s && s->in_use && s->mode == TS_MODE_SNAPSHOT) {
            uint8_t *bl_buf = (uint8_t *)net_alloc_buffer(0x100000);
            /* TS_RESCAN_ALIASING (client opt-in): acquire an alias ctx for the rescan read; mdbg is
               the floor (actx==NULL). The survivor set is per-connection, so this is single-thread. */
            scan_alias_ctx *rescan_actx = (cp->flags & TS_RESCAN_ALIASING)
                                        ? turboscan_alias_acquire(client_idx, s->pid) : NULL;
            uint64_t nc;
            if (s->value_length != value_length || !bl_buf) {
                nc = s->survivor_count;
            } else {
                nc = fs_snapshot_rescan(fd, s, cp->compareType, cp->valueType, value_length, turbo_cmp,
                                        pattern, mask, between_hi, includes_prev, mem_buf, bl_buf,
                                        rescan_actx);

                uint64_t rsz = 8 + s->value_length * (1 + (s->has_prev ? 1 : 0) + (s->has_first ? 1 : 0));
                if (nc > 0 && nc <= g_turboscan_materialize_max
                    && nc * TS_MATERIALIZE_DENSITY <= s->slot_count
                    && nc * rsz <= TS_RESIDENT_CAP) {
                    fs_snapshot_materialize(client_idx, s);
                }
            }

            uint64_t prog_sentinel = 0xFFFFFFFFFFFFFFFFULL;
            net_send_all(fd, &prog_sentinel, 8);
            if (bl_buf) free(bl_buf);
            net_send_all(fd, &nc, 8);
            free(chunk_buf); free(result_buf); free(mem_buf);
            if (pattern) free(pattern);
            if (mask)    free(mask);
            net_send_int32(fd, CMD_SUCCESS);
            return 0;
        }

        uint64_t new_count = 0;
        if (s && s->in_use && s->buf && s->value_length == value_length) {
            uint8_t  *recs     = (uint8_t *)s->buf;
            uint64_t  rec_size = s->rec_size;
            uint64_t  n        = s->count;
            uint64_t  window_start = 0, window_end = 0;
            /* TS_RESCAN_ALIASING (client opt-in): the cached window persists across survivor
               iterations, so the alias map is released when the window advances and at loop end. */
            scan_alias_ctx *rescan_actx = (cp->flags & TS_RESCAN_ALIASING)
                                        ? turboscan_alias_acquire(client_idx, s->pid) : NULL;
            const uint8_t *win_base = mem_buf;
            int            win_aliased = 0;

            for (uint64_t i = 0; i < n; i++) {
                if (turbo_cancel_pending(s->pid)) break;  /* cancel -> stop; s->count=new_count (partial) then terminator */
                uint8_t *rec = recs + i * rec_size;
                uint64_t addr;
                memcpy(&addr, rec, 8);
                const uint8_t *prev_ptr = includes_prev ? (rec + 8) : between_hi;

                if (addr < window_start || addr + value_length > window_end) {
                    window_start = addr;
                    uint64_t covered_end = addr + value_length;
                    for (uint64_t k = i + 1; k < n; k++) {
                        uint64_t na;
                        memcpy(&na, recs + k * rec_size, 8);
                        uint64_t gap = (na > covered_end) ? (na - covered_end) : 0;
                        if (gap > TS_RESCAN_GAP_MAX) break;
                        uint64_t ne = na + value_length;
                        if (ne - window_start > TS_RESCAN_WIN_CAP) break;
                        if (ne > covered_end) covered_end = ne;
                    }
                    uint64_t read_size = covered_end - window_start;
                    if (win_aliased) { scan_alias_release(rescan_actx); win_aliased = 0; }
                    win_base = fs_rescan_window_read(rescan_actx, s->pid, window_start, read_size,
                                                     mem_buf, &win_aliased);
                    window_end = window_start + read_size;
                }

                const uint8_t *mem_ptr = win_base + (addr - window_start);
                int matched = turbo_cmp
                    ? scan_point_compare(cp->compareType, cp->valueType,
                                         mem_ptr, pattern, prev_ptr)
                    : (int)proc_scan_compareValues(cp->compareType, cp->valueType, value_length,
                                                   pattern, mem_ptr, prev_ptr, mask);
                if (matched) {
                    uint8_t *out = recs + new_count * rec_size;

                    uint64_t prev_off  = 8 + value_length;
                    uint64_t first_off = 8 + value_length + (s->has_prev ? value_length : 0);
                    uint8_t prevval[8], firstval[8];
                    if (s->has_prev)  memcpy(prevval,  rec + 8,        value_length);
                    if (s->has_first) memcpy(firstval, rec + first_off, value_length);
                    memcpy(out, &addr, 8);
                    memcpy(out + 8, mem_ptr, value_length);
                    if (s->has_prev)  memcpy(out + prev_off,  prevval,  value_length);
                    if (s->has_first) memcpy(out + first_off, firstval, value_length);
                    new_count++;
                }
            }
            if (win_aliased) scan_alias_release(rescan_actx);
            s->count = new_count;
        } else if (s && s->in_use) {
            new_count = s->count;
        }

        uint64_t prog_sentinel = 0xFFFFFFFFFFFFFFFFULL;
        net_send_all(fd, &prog_sentinel, 8);
        net_send_all(fd, &new_count, 8);
        free(chunk_buf);
        free(result_buf);
        free(mem_buf);
        if (pattern) free(pattern);
        if (mask)    free(mask);
        net_send_int32(fd, CMD_SUCCESS);
        return 0;
    }

    /* TS_RESCAN_ALIASING (client opt-in): client-driven CC12 reads each chunk's clustered windows;
       mapped+released per window. mdbg floor (actx==NULL). */
    scan_alias_ctx *rescan_actx = (cp->flags & TS_RESCAN_ALIASING)
                                ? turboscan_alias_acquire(client_idx, cp->pid) : NULL;
    for (;;) {
        uint32_t chunk_len = 0;
        net_recv_all(fd, &chunk_len, 4, 1);
        if (chunk_len == 0xFFFFFFFFu) break;
        if (chunk_len == 0) {
            uint64_t per_chunk_sentinel = 0xFFFFFFFFFFFFFFFFULL;
            net_send_all(fd, &per_chunk_sentinel, 8);
            continue;
        }
        if (chunk_len > 0x40000u) break;

        net_recv_all(fd, chunk_buf, (int)chunk_len, 1);

        uint64_t window_start = 0;
        uint64_t window_end   = 0;
        uint64_t result_len   = 0;
        const uint8_t *win_base = mem_buf;
        int            win_aliased = 0;

        for (uint64_t off = 0; off + entry_size <= chunk_len; off += entry_size) {
            uint32_t entry_offset;
            memcpy(&entry_offset, chunk_buf + off, 4);
            const uint8_t *prev_value_ptr = includes_prev ? (chunk_buf + off + 4) : between_hi;
            uint64_t addr = cp->base_address + entry_offset;

            if (addr < window_start || addr + value_length > window_end) {

                window_start = addr;
                uint64_t covered_end = addr + value_length;
                for (uint64_t k = off + entry_size; k + entry_size <= chunk_len; k += entry_size) {
                    uint32_t next_off;
                    memcpy(&next_off, chunk_buf + k, 4);
                    uint64_t next_addr = cp->base_address + next_off;
                    uint64_t gap = (next_addr > covered_end) ? (next_addr - covered_end) : 0;
                    if (gap > TS_RESCAN_GAP_MAX) break;
                    uint64_t next_end = next_addr + value_length;
                    if (next_end - window_start > TS_RESCAN_WIN_CAP) break;
                    if (next_end > covered_end) covered_end = next_end;
                }
                uint64_t read_size = covered_end - window_start;
                if (win_aliased) { scan_alias_release(rescan_actx); win_aliased = 0; }
                win_base = fs_rescan_window_read(rescan_actx, cp->pid, window_start, read_size,
                                                 mem_buf, &win_aliased);
                window_end = window_start + read_size;
            }

            const uint8_t *mem_value_ptr = win_base + (addr - window_start);

            int matched = turbo_cmp
                ? scan_point_compare(cp->compareType, cp->valueType,
                                     mem_value_ptr, pattern, prev_value_ptr)
                : (int)proc_scan_compareValues(cp->compareType, cp->valueType, value_length,
                                               pattern, mem_value_ptr, prev_value_ptr, mask);
            if (matched) {
                if (result_len > flush_thresh) {
                    *(uint64_t *)result_buf = result_len;
                    net_send_all(fd, result_buf, (int)(result_len + 8));
                    result_len = 0;
                }
                memcpy(result_buf + 8 + result_len,     &entry_offset, 4);
                memcpy(result_buf + 8 + result_len + 4, mem_value_ptr, value_length);
                result_len += 4 + value_length;
            }
        }
        if (win_aliased) scan_alias_release(rescan_actx);

        if (result_len) {
            *(uint64_t *)result_buf = result_len;
            net_send_all(fd, result_buf, (int)(result_len + 8));
        }

        uint64_t per_chunk_sentinel = 0xFFFFFFFFFFFFFFFFULL;
        net_send_all(fd, &per_chunk_sentinel, 8);
    }

    free(chunk_buf);
    free(result_buf);
    free(mem_buf);
    if (pattern) free(pattern);
    if (mask)    free(mask);

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int proc_turboscan_get_handle(int fd, struct cmd_packet *packet, unsigned char client_idx) {
    if (!(g_proc_auth_state & 2)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    struct cmd_proc_turboscan_get_packet *gp =
        (struct cmd_proc_turboscan_get_packet *)packet->data;
    if (!gp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    struct turboscan_session *s = fs_session_get(client_idx);
    if (!s || !s->in_use || (s->mode == TS_MODE_LIST && !s->buf)) {
        net_send_int32(fd, CMD_SUCCESS);
        uint32_t zero = 0;
        net_send_all(fd, &zero, 4);
        net_send_int32(fd, CMD_SUCCESS);
        return 0;
    }

    if (s->mode == TS_MODE_SNAPSHOT) {
        uint8_t *out_buf = (uint8_t *)net_alloc_buffer(0x40000);
        if (!out_buf) {
            net_send_int32(fd, CMD_DATA_NULL);
            return 1;
        }
        net_send_int32(fd, CMD_SUCCESS);
        fs_snapshot_get(fd, s, gp->start_index, gp->count, out_buf, 0x40000);
        free(out_buf);
        net_send_int32(fd, CMD_SUCCESS);
        return 0;
    }

    uint64_t value_length = s->value_length;
    uint64_t rec_size     = s->rec_size;
    uint64_t total        = s->count;
    uint64_t start        = gp->start_index;
    uint64_t want         = gp->count;
    if (start > total) start = total;
    uint64_t end = start + want;
    if (end > total || end < start) end = total;
    uint32_t actual = (uint32_t)(end - start);

    uint8_t *out_buf = (uint8_t *)net_alloc_buffer(0x40000);
    if (!out_buf) {
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }

    int has_first = s->has_first, has_prev = s->has_prev;

    uint64_t rec_prev_off  = has_prev ? (8 + value_length) : 8;
    uint64_t rec_first_off = 8 + value_length + (has_prev ? value_length : 0);
    net_send_int32(fd, CMD_SUCCESS);
    uint32_t hdr = actual | (has_first ? 0x80000000u : 0u);
    net_send_all(fd, &hdr, 4);

    uint8_t  *recs = (uint8_t *)s->buf;
    uint64_t  ent_size = 8 + value_length * (has_first ? 3 : 2);
    uint64_t  out_len = 0;
    uint64_t  out_cap = 0x40000;

    for (uint64_t i = start; i < end; i++) {
        uint8_t *rec = recs + i * rec_size;
        if (out_len + ent_size > out_cap) {
            net_send_all(fd, out_buf, (int)out_len);
            out_len = 0;
        }
        uint8_t *o = out_buf + out_len;
        memcpy(o,     rec,                  8);
        memcpy(o + 8, rec + 8, value_length);
        memcpy(o + 8 + value_length, rec + rec_prev_off, value_length);
        if (has_first)
            memcpy(o + 8 + 2 * value_length, rec + rec_first_off, value_length);
        out_len += ent_size;
    }
    if (out_len) net_send_all(fd, out_buf, (int)out_len);

    free(out_buf);
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int proc_turboscan_end_handle(int fd, struct cmd_packet *packet, unsigned char client_idx) {
    (void)packet;
    if (!(g_proc_auth_state & 2)) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    turboscan_session_free_idx(client_idx);
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}
