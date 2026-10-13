// SPDX-License-Identifier: GPL-3.0-only
//
// Host test server for the pointer-scan command (0xBDAACC30).
//
// Builds the real debugger/source/ptr_scan.c and ptr_scan_core.c natively and replaces the
// console pieces (mmap syscall, klog, process reads, aliasing, page-table probe) with small
// stand-ins, then serves the ps5debug-NG packet format on 127.0.0.1:<port>.  Driven by
// test_ptrscan.py.
//
//   harness <port> [--image FILE] [--fill BASE SIZE VALUE] [--fail LO HI]... [--noauth]
//
//   --image FILE        memory = FILE: u64 base address, then the bytes
//   --fill B S V        memory [B, B+S) where every 8-byte slot holds V (no RAM needed)
//   --fail LO HI        reads that touch [LO, HI) fail (unmapped mid-pass, process exiting)
//   --noauth            g_proc_auth_state = 0
//
// kill -USR1 <harness pid> acts like 0xBDAACC17 for pid 1 (cancel the running pass).
//
// After each request it prints "HANDLER rc=<return value> ms=<time>" to stdout.
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "net.h"
#include "proc.h"
#include "protocol.h"
#include "ptr_scan.h"
#include "scan_alias.h"

uint32_t g_proc_auth_state = 2;
volatile int g_turboscan_cancel_pid = 0;

/* ---- console stand-ins -------------------------------------------------------------- */
long __crt_syscall(long no, ...) {
    va_list ap;
    va_start(ap, no);
    long a = va_arg(ap, long), b = va_arg(ap, long);
    va_end(ap);
    if (no == 477) {                                   /* mmap(0, len, RW, MAP_PRIVATE|ANON, -1, 0) */
        void *m = mmap(0, (size_t)b, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return m == MAP_FAILED ? -1 : (long)m;
    }
    if (no == 73) return munmap((void *)a, (size_t)b); /* munmap */
    return -1;
}
int klog_puts(const char *s) { fprintf(stderr, "KLOG %s", s); return 0; }

static uint8_t *img;                                   /* --image */
static uint64_t mem_base, mem_len, fill_value;
static int fill_mode;
static uint64_t fail_lo[16], fail_hi[16];
static int nfail;
static uint64_t reads_failed;

int proc_read_mem_checked(uint32_t pid, uint64_t addr, uint64_t len, void *buf) {
    (void)pid;
    for (int i = 0; i < nfail; i++)
        if (addr < fail_hi[i] && addr + len > fail_lo[i]) { reads_failed++; return 1; }
    if (addr < mem_base || addr + len > mem_base + mem_len || addr + len < addr) { reads_failed++; return 1; }
    if (fill_mode) {
        uint8_t *p = (uint8_t *)buf;
        for (uint64_t o = 0; o < len; o += 8) memcpy(p + o, &fill_value, len - o >= 8 ? 8 : len - o);
    } else {
        memcpy(buf, img + (addr - mem_base), len);
    }
    return 0;
}
void proc_read_mem(uint32_t pid, uint64_t addr, uint64_t len, void *buf) {
    memset(buf, 0, len);
    (void)proc_read_mem_checked(pid, addr, len, buf);
}
int proc_ptwalk_probe(uint32_t pid, uint64_t va, uint64_t *phys, int *level, uint64_t *pgsz, uint64_t *pte) {
    (void)pid; (void)va; *phys = 0; *level = 0; *pgsz = 0; *pte = 0;
    return -1;
}
/* No aliasing on the host: every chunk takes the proc_read_mem_checked path. */
scan_alias_ctx *scan_alias_begin(uint32_t pid, uint64_t cap) { (void)pid; (void)cap; return NULL; }
const void *scan_alias_map(scan_alias_ctx *c, uint64_t t, uint64_t l, uint64_t *o) {
    (void)c; (void)t; (void)l; (void)o; return NULL;
}
void scan_alias_release(scan_alias_ctx *c) { (void)c; }
void scan_alias_end(scan_alias_ctx *c) { (void)c; }

/* ---- the real net.c behaviour (send/recv loops, bit-swapped status words) ------------- */
int net_send_all(int fd, const void *buf, int len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, (size_t)len, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        p += n; len -= (int)n;
    }
    return 0;
}
int net_recv_all(int fd, void *buf, int len, int force) {
    char *p = (char *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, (size_t)len, force ? MSG_WAITALL : 0);
        if (n <= 0) return -1;
        p += n; len -= (int)n;
    }
    return 0;
}
static uint32_t bitswap32(uint32_t x) { return ((x >> 1) & 0x55555555u) | ((x << 1) & 0xAAAAAAAAu); }
int net_send_int32(int fd, uint32_t v) { uint32_t w = bitswap32(v); return net_send_all(fd, &w, 4); }

static void on_usr1(int sig) { (void)sig; g_turboscan_cancel_pid = 1; }

/* ---- server ---------------------------------------------------------------------------- */
static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: harness <port> [options]\n"); return 2; }
    int port = atoi(argv[1]);
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--image") && i + 1 < argc) {
            FILE *f = fopen(argv[++i], "rb");
            if (!f) { perror("image"); return 2; }
            if (fread(&mem_base, 8, 1, f) != 1) return 2;
            fseek(f, 0, SEEK_END); mem_len = (uint64_t)ftell(f) - 8; fseek(f, 8, SEEK_SET);
            img = malloc(mem_len);
            if (fread(img, 1, mem_len, f) != mem_len) return 2;
            fclose(f);
        } else if (!strcmp(argv[i], "--fill") && i + 3 < argc) {
            fill_mode = 1;
            mem_base = strtoull(argv[++i], 0, 0);
            mem_len = strtoull(argv[++i], 0, 0);
            fill_value = strtoull(argv[++i], 0, 0);
        } else if (!strcmp(argv[i], "--fail") && i + 2 < argc && nfail < 16) {
            fail_lo[nfail] = strtoull(argv[++i], 0, 0);
            fail_hi[nfail++] = strtoull(argv[++i], 0, 0);
        } else if (!strcmp(argv[i], "--noauth")) {
            g_proc_auth_state = 0;
        } else {
            fprintf(stderr, "unknown option %s\n", argv[i]);
            return 2;
        }
    }
    signal(SIGUSR1, on_usr1);
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) || listen(s, 4)) { perror("bind"); return 2; }
    printf("ready\n");
    fflush(stdout);
    for (;;) {                                         /* one client at a time, like handle_client */
        int c = accept(s, 0, 0);
        if (c < 0) continue;
        for (;;) {
            uint32_t hdr[3];                           /* magic, cmd, datalen */
            if (net_recv_all(c, hdr, 12, 1)) break;
            uint8_t body[256];
            if (hdr[2] > sizeof(body) || (hdr[2] && net_recv_all(c, body, (int)hdr[2], 1))) break;
            struct cmd_packet p;
            memset(&p, 0, sizeof(p));
            p.magic = hdr[0]; p.cmd = hdr[1]; p.datalen = hdr[2]; p.data = body;
            if (hdr[1] != 0xBDAACC30u) { net_send_int32(c, CMD_ERROR); continue; }
            long t0 = now_ms();
            int rc = proc_ptrscan_handle(c, &p);
            printf("HANDLER rc=%d ms=%ld reads_failed=%llu\n", rc, now_ms() - t0, (unsigned long long)reads_failed);
            fflush(stdout);
            if (rc) break;                             /* nonzero: handle_client drops the client */
        }
        close(c);
    }
}
