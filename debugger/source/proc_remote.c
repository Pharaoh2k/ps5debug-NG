// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "proc.h"
#include "kern_rw_fast.h"
#include "debug_state.h"

#include <stdarg.h>
#include <sys/mman.h>

#define PCRK_SIZEOF_REG  0xb0
#define PCRK_R_R10       0x28
#define PCRK_R_R9        0x30
#define PCRK_R_R8        0x38
#define PCRK_R_RDI       0x40
#define PCRK_R_RSI       0x48
#define PCRK_R_RDX       0x60
#define PCRK_R_RCX       0x68
#define PCRK_R_RAX       0x70
#define PCRK_R_RIP       0x88
#define PCRK_R_RSP       0xa0

#define NID_LIBKERNEL_SYSCALL  "W0xkN0+ZkCE"

static void *g_server_mutex = (void *)0;
static int   g_server_mutex_init_done = 0;

static void mutex_lock(void)   {
    if (!g_server_mutex_init_done) {
        scePthreadMutexInit(&g_server_mutex, (void *)0, "proc_remote");
        g_server_mutex_init_done = 1;
    }
    scePthreadMutexLock(&g_server_mutex);
}
static void mutex_unlock(void) { scePthreadMutexUnlock(&g_server_mutex); }
static void debugger_usleep(unsigned long us) { sceKernelUsleep((unsigned int)us); }

extern long __crt_syscall(long sysno, ...);

long ptrace_raw(int op, int pid, void *addr, int data) {

    return ps5debug_syscall(26 , (long)op, (long)pid, (long)addr, (long)data, 0L, 0L);
}

#if 0
extern int sceKernelSendNotificationRequest(int unused, void *req,
                                             size_t reqsz, int flag);

static void caveat4_diag(int self_pid) {
    char buf[1024];
    uint8_t sdk_caps [16] = {0};
    uint8_t fast_caps[16] = {0};

    intptr_t sdk_kproc  = kernel_get_proc(self_pid);
    intptr_t fast_kproc = kernel_get_proc_fast(self_pid);

    intptr_t sdk_ucred  = kernel_get_proc_ucred(self_pid);
    intptr_t fast_ucred = kernel_get_proc_ucred_fast(self_pid);

    uint64_t sdk_authid  = kernel_get_ucred_authid(self_pid);
    uint64_t fast_authid = kernel_get_ucred_authid_fast(self_pid);

    int sdk_caps_rc  = kernel_get_ucred_caps(self_pid,  sdk_caps);
    int fast_caps_rc = kernel_get_ucred_caps_fast(self_pid, fast_caps);

    uint64_t saved_authid = fast_authid;
    uint8_t  saved_caps[16];
    memcpy(saved_caps, fast_caps, 16);

    uint8_t all_ones[16];
    memset(all_ones, 0xFF, 16);

    int set_authid_rc = kernel_set_ucred_authid_fast(self_pid, 0x4800000000010003ULL);

    uint64_t authid_after_set = kernel_get_ucred_authid_fast(self_pid);

    uint64_t sdk_authid_after = kernel_get_ucred_authid(self_pid);

    int set_caps_rc = kernel_set_ucred_caps_fast(self_pid, all_ones);
    uint8_t caps_after_set[16] = {0};
    kernel_get_ucred_caps_fast(self_pid, caps_after_set);

    int restore_authid_rc = kernel_set_ucred_authid_fast(self_pid, saved_authid);
    int restore_caps_rc   = kernel_set_ucred_caps_fast(self_pid, saved_caps);

    uint64_t authid_after_restore = kernel_get_ucred_authid_fast(self_pid);
    uint8_t  caps_after_restore[16] = {0};
    kernel_get_ucred_caps_fast(self_pid, caps_after_restore);

    int snlen = snprintf(buf, sizeof(buf),
        "C4-DIAG pid=%d\n"
        "READ kproc:  SDK=%lx FAST=%lx %s\n"
        "READ ucred:  SDK=%lx FAST=%lx %s\n"
        "READ authid: SDK=%lx FAST=%lx %s\n"
        "READ caps:   SDK rc=%d %02x%02x%02x%02x%02x%02x%02x%02x\n"
        "             FAST rc=%d %02x%02x%02x%02x%02x%02x%02x%02x %s\n"
        "WRITE set_authid(debug) FAST rc=%d after_FAST=%lx after_SDK=%lx\n"
        "WRITE set_caps(0xFF*16) FAST rc=%d after_caps=%02x%02x%02x%02x%02x%02x%02x%02x\n"
        "RESTORE set_authid(saved) FAST rc=%d\n"
        "RESTORE set_caps(saved)   FAST rc=%d\n"
        "VERIFY authid: %lx %s\n"
        "VERIFY caps  : %02x%02x%02x%02x%02x%02x%02x%02x %s\n",
        self_pid,
        (unsigned long)sdk_kproc, (unsigned long)fast_kproc,
            (sdk_kproc == fast_kproc) ? "MATCH" : "DIFFER",
        (unsigned long)sdk_ucred, (unsigned long)fast_ucred,
            (sdk_ucred == fast_ucred) ? "MATCH" : "DIFFER",
        (unsigned long)sdk_authid, (unsigned long)fast_authid,
            (sdk_authid == fast_authid) ? "MATCH" : "DIFFER",
        sdk_caps_rc,
        sdk_caps[0], sdk_caps[1], sdk_caps[2], sdk_caps[3],
        sdk_caps[4], sdk_caps[5], sdk_caps[6], sdk_caps[7],
        fast_caps_rc,
        fast_caps[0], fast_caps[1], fast_caps[2], fast_caps[3],
        fast_caps[4], fast_caps[5], fast_caps[6], fast_caps[7],
        (memcmp(sdk_caps, fast_caps, 16) == 0) ? "MATCH" : "DIFFER",
        set_authid_rc, (unsigned long)authid_after_set, (unsigned long)sdk_authid_after,
        set_caps_rc,
        caps_after_set[0], caps_after_set[1], caps_after_set[2], caps_after_set[3],
        caps_after_set[4], caps_after_set[5], caps_after_set[6], caps_after_set[7],
        restore_authid_rc, restore_caps_rc,
        (unsigned long)authid_after_restore,
            (authid_after_restore == saved_authid) ? "OK" : "BAD",
        caps_after_restore[0], caps_after_restore[1], caps_after_restore[2], caps_after_restore[3],
        caps_after_restore[4], caps_after_restore[5], caps_after_restore[6], caps_after_restore[7],
        (memcmp(caps_after_restore, saved_caps, 16) == 0) ? "OK" : "BAD");
    (void)snlen;

    klog_puts(buf);
    typedef struct { char useless1[45]; char message[3075]; } req_t;
    req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, buf, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

}
#endif

int elev_save_and_set(struct elev_state *st) {
    int self = getpid();
    st->valid = 0;

    intptr_t ucred = kernel_get_proc_ucred_fast((pid_t)self);
    if (ucred == 0) return -1;

    if (kernel_copyout_fast(ucred + 0x58, &st->saved_authid, sizeof(st->saved_authid)) != 0) return -1;
    if (st->saved_authid == 0) return -1;
    if (kernel_copyout_fast(ucred + 0x60, st->saved_caps, 0x10) != 0) return -1;

    uint64_t priv_authid = 0x4800000000010003ULL;
    if (kernel_copyin_fast(&priv_authid, ucred + 0x58, sizeof(priv_authid)) != 0) return -1;
    uint8_t all_ones[16];
    memset(all_ones, 0xFF, 16);
    if (kernel_copyin_fast(all_ones, ucred + 0x60, 0x10) != 0) {
        kernel_copyin_fast(&st->saved_authid, ucred + 0x58, sizeof(st->saved_authid));
        return -1;
    }
    st->valid = 1;
    return 0;
}

void elev_restore(struct elev_state *st) {
    if (!st->valid) return;
    int self = getpid();
    intptr_t ucred = kernel_get_proc_ucred_fast((pid_t)self);
    if (ucred != 0) {
        kernel_copyin_fast(&st->saved_authid, ucred + 0x58, sizeof(st->saved_authid));
        kernel_copyin_fast(st->saved_caps, ucred + 0x60, 0x10);
    }
    st->valid = 0;
}

long ptrace_elev(int op, int pid, void *addr, int data) {
    struct elev_state es;
    if (elev_save_and_set(&es) != 0) return -1;
    long rc = ptrace_raw(op, pid, addr, data);
    elev_restore(&es);
    return rc;
}

extern int *__error(void);
int kern_ptrace_attach_and_wait(int pid)
{
    if (ptrace_elev(0x0A , pid, 0, 0) == -1) return -1;

    static int s_first_w4_diag = 0;

    int wait_status = 0;
    *__error() = 0;
    long wait_rc = ps5debug_syscall(7 , (long)pid, (long)&wait_status, 0L, 0L, 0L, 0L);
    int  wait_errno = *__error();

    if (!s_first_w4_diag) {
        s_first_w4_diag = 1;
        klog_printf("[diag] kern_ptrace_attach_and_wait FIRST - pid=%d wait4 rc=%ld errno=%d status=0x%x\n",
                    pid, wait_rc, wait_errno, wait_status);
    }

    if (wait_rc == -1) {

        sceKernelUsleep(20000);
    }
    return 0;
}

static int resume_app_via_self_id(int pid)
{
    int app_id = 0;
    int rc = _sceApplicationGetAppId(pid, &app_id);
    if (rc != 0) return rc;
    return sceApplicationContinue(app_id);
}

int pt_detach(int pid) {
    return (ptrace_elev(0x0B , pid, 0, 0) == -1) ? -1 : 0;
}

extern void    *curdbgctx;
struct dbgctx_pid { uint32_t pid; };

int proc_rpc_stop_target(int wpid)
{
    struct dbgctx_pid *ctx = (struct dbgctx_pid *)curdbgctx;
    uint32_t state = g_stopgo_last_signal;
    int hit_second_kill = 0;

    if (ctx != NULL) {
        int target_pid = (int)ctx->pid;
        if (state == 0x11 && g_stopgo_target_pid == (uint32_t)wpid) {
            resume_app_via_self_id(wpid);
            if (target_pid == wpid) {
                ptrace_elev(7 , wpid, (void *)1, 0);
                kill(wpid, 0x11 );
                waitpid(wpid, NULL, 0);
                return 0;
            }
            hit_second_kill = 1;
        } else if (target_pid == wpid) {

            kill(wpid, 0x11);
            waitpid(wpid, NULL, 0);
            return 0;
        }
    } else if (state == 0x11 && g_stopgo_target_pid == (uint32_t)wpid) {
        resume_app_via_self_id(wpid);
        hit_second_kill = 1;
    }

    if (hit_second_kill) {
        kill(wpid, 0x13 );
        waitpid(wpid, NULL, 0);
    }

    int rc = kern_ptrace_attach_and_wait(wpid);
    return rc ? -1 : 0;
}

int proc_detach_or_stop(int pid)
{
    struct dbgctx_pid *ctx = (struct dbgctx_pid *)curdbgctx;
    uint32_t state = g_stopgo_last_signal;

    if (ctx != NULL && (int)ctx->pid == pid) {
        if (state == 0x11) {
            uint32_t bound_pid = g_stopgo_target_pid;
            resume_app_via_self_id(pid);
            ptrace_elev(7 , pid, (void *)1, 0);
            if (bound_pid != (uint32_t)pid) return 0;
            kill(pid, 0x11);
            waitpid(pid, NULL, 0);
            return 0;
        }

        resume_app_via_self_id(pid);
        ptrace_elev(7, pid, (void *)1, 0);
        return 0;
    }

    if (state == 0x11) {
        uint32_t bound_pid = g_stopgo_target_pid;
        resume_app_via_self_id(pid);
        int rc = pt_detach(pid);
        if (rc != 0) return -1;
        if (bound_pid == (uint32_t)pid) {
            kill(pid, 0x11);
            waitpid(pid, NULL, 0);
        }
        return 0;
    }

    resume_app_via_self_id(pid);
    int rc = pt_detach(pid);
    return rc ? -1 : 0;
}

__attribute__((noinline))
uint64_t proc_call_remote_kern(int pid, uint64_t func_addr, ...)
{
    uint8_t  saved_regs   [PCRK_SIZEOF_REG];
    uint8_t  modified_regs[PCRK_SIZEOF_REG];
    uint64_t kdata;
    int      status = 0;

    void *proc = (void *)kernel_get_proc_fast(pid);
    if (proc == 0) return (uint64_t)-1;
    uint64_t kdata_u = kernel_dynlib_mapbase_addr_by_proc_fast(proc, 0x2001);
    if (kdata_u == (uint64_t)-1 || kdata_u == 0) return (uint64_t)-1;
    kdata = kdata_u;

    if (ptrace_elev(0x21 , pid, saved_regs, 0) != 0)
        return (uint64_t)-1;

    memcpy(modified_regs, saved_regs, PCRK_SIZEOF_REG);

    *(uint64_t *)(modified_regs + PCRK_R_RIP)  = func_addr;
    *(uint64_t *)(modified_regs + PCRK_R_RSP) -= 8;

    {
        va_list ap;
        va_start(ap, func_addr);
        *(uint64_t *)(modified_regs + PCRK_R_RDI) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RSI) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RDX) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RCX) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R8 ) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R9 ) = va_arg(ap, uint64_t);
        va_end(ap);
    }

    if (ptrace_elev(0x22 , pid, modified_regs, 0) != 0)
        return (uint64_t)-1;

    {
        uint64_t target_rsp = *(uint64_t *)(modified_regs + PCRK_R_RSP);
        sys_proc_rw_w1((uint64_t)pid, target_rsp, 8, &kdata, 0);
    }

    ptrace_elev(7 , pid, (void *)1, 0);
    waitpid(pid, &status, 0);

    if (ptrace_elev(0x21 , pid, modified_regs, 0) != 0)
        return (uint64_t)-1;
    if (ptrace_elev(0x22 , pid, saved_regs, 0) != 0)
        return (uint64_t)-1;

    return *(uint64_t *)(modified_regs + PCRK_R_RAX);
}

__attribute__((noinline))
uint64_t proc_call_remote_sys(int pid, int sysno, ...)
{
    uint8_t saved_regs   [PCRK_SIZEOF_REG];
    uint8_t modified_regs[PCRK_SIZEOF_REG];

    uint64_t nid_addr = kernel_dynlib_resolve_fast(pid, 1, NID_LIBKERNEL_SYSCALL);
    if (nid_addr == 0) {
        nid_addr = kernel_dynlib_resolve_fast(pid, 0x2001, NID_LIBKERNEL_SYSCALL);
        if (nid_addr == 0) return (uint64_t)-1;
    }

    int step_pid = pid;
    int numlwps = (int)ptrace_elev(0x0E , pid, 0, 0);
    if (numlwps > 0) {
        int *lwp_buf = (int *)malloc((unsigned long)numlwps * 4u);
        if (lwp_buf != 0) {
            ptrace_elev(0x0F , pid, lwp_buf, numlwps);
            step_pid = lwp_buf[0];
            free(lwp_buf);
        }
    }

    if (ptrace_elev(0x21 , pid, saved_regs, 0) != 0)
        return (uint64_t)-1;

    nid_addr += 0x0A;
    memcpy(modified_regs, saved_regs, PCRK_SIZEOF_REG);

    *(uint64_t *)(modified_regs + PCRK_R_RIP) = (uint64_t)nid_addr;
    *(uint64_t *)(modified_regs + PCRK_R_RAX) = (uint64_t)(int64_t)sysno;

    {
        va_list ap;
        va_start(ap, sysno);
        *(uint64_t *)(modified_regs + PCRK_R_RDI) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RSI) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RDX) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R10) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R8 ) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R9 ) = va_arg(ap, uint64_t);
        va_end(ap);
    }

    if (ptrace_elev(0x22 , pid, modified_regs, 0) != 0)
        return (uint64_t)-1;

    int success = (*(uint64_t *)(modified_regs + PCRK_R_RSP) >
                   *(uint64_t *)(saved_regs    + PCRK_R_RSP));

    for (int retry = 0; retry < 3 && !success; retry++) {
        if (ptrace_elev(9 , step_pid, (void *)(uintptr_t)1, 0) != 0)
            return (uint64_t)-1;
        if ((int)waitpid(pid, 0, 0) < 0)
            return (uint64_t)-1;
        if (ptrace_elev(0x21, pid, modified_regs, 0) != 0)
            return (uint64_t)-1;
        success = (*(uint64_t *)(modified_regs + PCRK_R_RSP) >
                   *(uint64_t *)(saved_regs    + PCRK_R_RSP));
    }
    if (!success) {
        if (ptrace_elev(9, step_pid, (void *)(uintptr_t)1, 0) != 0)
            return (uint64_t)-1;
        if ((int)waitpid(pid, 0, 0) < 0)
            return (uint64_t)-1;
        if (ptrace_elev(0x21, pid, modified_regs, 0) != 0)
            return (uint64_t)-1;

    }

    int set_rc = (int)ptrace_elev(0x22, pid, saved_regs, 0);
    uint64_t result = success
        ? *(uint64_t *)(modified_regs + PCRK_R_RAX)
        : (uint64_t)-1;
    if (set_rc != 0) result = (uint64_t)-1;
    return result;
}

void *freebsd_mmap(unsigned long pid, void *addr, unsigned long length,
                          int prot, int flags, int fd, long offset)
{
    return (void *)proc_call_remote_sys(
        (int)pid, 0x1DD, addr, length, prot, flags, fd, offset, 0L);
}

int freebsd_munmap(int pid, unsigned long addr, unsigned long len)
{
    return (int)proc_call_remote_sys(pid, 0x49, addr, len);
}

int sys_proc_alloc(uint32_t pid, void **out_addr_ptr, uint64_t length)
{
    length = (length + 0x3fffull) & ~0x3fffull;
    if (out_addr_ptr == 0) return 1;

    int my_pid = getpid();

    if (my_pid == (int)pid) {

        void *result = mmap(*out_addr_ptr, (size_t)length, 7, 0x1002, -1, 0);
        *out_addr_ptr = result;
        uint64_t a = (uint64_t)result - 1;
        if (a > 0xfffffffffffffffdull) return -1;

        memset(result, 0, (size_t)length);
        return 0;
    }

    if (proc_rpc_stop_target((int)pid) != 0) return -1;

    void *result = freebsd_mmap((unsigned long)pid, *out_addr_ptr,
                                 (unsigned long)length, 7, 0x1002, -1, 0);
    *out_addr_ptr = result;

    if ((intptr_t)result != -1L) {
        kernel_mprotect((pid_t)pid, (intptr_t)result, (size_t)length, 7);

        proc_call_remote_sys((int)pid, 203, (long)(intptr_t)result, (long)length);
    }

    if (proc_detach_or_stop((int)pid) != 0) return -1;

    void *final = *out_addr_ptr;
    uint64_t a = (uint64_t)final - 1;
    if (a > 0xfffffffffffffffdull) return -1;
    return 0;
}

int sys_proc_free(uint32_t pid, void *addr, uint64_t length)
{
    length = (length + 0x3fffull) & ~0x3fffull;
    if (addr == 0) return 1;

    int my_pid = getpid();
    if (my_pid == (int)pid) {
        return munmap(addr, (size_t)length);
    }

    if (proc_rpc_stop_target((int)pid) != 0) return -1;

    int rc = freebsd_munmap((int)pid, (unsigned long)(uintptr_t)addr,
                             (unsigned long)length);

    if (proc_detach_or_stop((int)pid) != 0) return -1;

    return (rc >= 0) ? rc : -1;
}

int sys_proc_call(int pid, struct sys_proc_call_args *args)
{
    if (proc_rpc_stop_target(pid) != 0) return -1;

    uint64_t ret = proc_call_remote_kern(
        pid, args->rip,
        args->rdi, args->rsi, args->rdx, args->rcx, args->r8, args->r9);

    if (ret == (uint64_t)-1) {
        proc_detach_or_stop(pid);
        return -1;
    }

    args->rax = ret;
    int rc = proc_detach_or_stop(pid);
    return rc ? -1 : 0;
}

#define ARENA_ALIGN  0x4000ULL
#define ARENA_CHUNK  (16ULL * 1024 * 1024)
#define ARENA_NPID   4

#define ALLOC_FILL_RETRIES  5

struct arena_seg { uint64_t base, size, used; struct arena_seg *next; };
struct arena_blk { uint64_t addr, size;       struct arena_blk *next; };
struct arena_pid {
    int               inuse;
    uint32_t          pid;
    struct arena_seg *segs;
    struct arena_blk *freelist;
    uint64_t          next_seg_size;   /* grow-on-demand target; 0 = use request size */
};
static struct arena_pid g_arenas[ARENA_NPID];
static int g_arena_enabled = 1;

static uint64_t arena_round(uint64_t n) { return (n + (ARENA_ALIGN - 1)) & ~(ARENA_ALIGN - 1); }

static struct arena_pid *arena_get(uint32_t pid) {
    int slot = -1;
    for (int i = 0; i < ARENA_NPID; i++) {
        if (g_arenas[i].inuse && g_arenas[i].pid == pid) return &g_arenas[i];
        if (!g_arenas[i].inuse && slot < 0) slot = i;
    }
    if (slot < 0) slot = 0;
    struct arena_pid *ap = &g_arenas[slot];
    for (struct arena_seg *s = ap->segs; s; ) { struct arena_seg *n = s->next; free(s); s = n; }
    for (struct arena_blk *b = ap->freelist; b; ) { struct arena_blk *n = b->next; free(b); b = n; }
    ap->inuse = 1; ap->pid = pid; ap->segs = 0; ap->freelist = 0; ap->next_seg_size = 0;
    return ap;
}

static struct arena_pid *arena_find(uint32_t pid) {
    for (int i = 0; i < ARENA_NPID; i++)
        if (g_arenas[i].inuse && g_arenas[i].pid == pid) return &g_arenas[i];
    return 0;
}

static int do_real_alloc(uint32_t pid, uint64_t *out, uint64_t length, uint64_t hint) {
    void *p = (void *)(uintptr_t)hint;
    int rc = sys_proc_alloc(pid, &p, length);
    if (rc != 0) {
        p = (void *)(uintptr_t)hint;
        debugger_usleep(40000);
        int retries = ALLOC_FILL_RETRIES;
        for (;;) {
            rc = sys_proc_alloc(pid, &p, length);
            if (rc == 0) break;
            p = (void *)(uintptr_t)hint;
            debugger_usleep(40000);
            if (--retries == 0) { *out = (uint64_t)(uintptr_t)p; return rc; }
        }
    }
    *out = (uint64_t)(uintptr_t)p;
    return 0;
}

static int do_real_free(uint32_t pid, uint64_t addr, uint64_t length) {
    int rc = sys_proc_free(pid, (void *)(uintptr_t)addr, length);
    if (rc < 0) {
        int retries = 11;
        do {
            debugger_usleep(40000);
            if (sys_proc_free(pid, (void *)(uintptr_t)addr, length) >= 0) { rc = 0; break; }
        } while (--retries > 0);
    }
    return rc;
}

static int arena_alloc(uint32_t pid, uint64_t length, uint64_t *out) {
    uint64_t size = arena_round(length ? length : ARENA_ALIGN);
    struct arena_pid *ap = arena_get(pid);

    struct arena_blk **pp = &ap->freelist;
    for (struct arena_blk *b = ap->freelist; b; pp = &b->next, b = b->next) {
        if (b->size >= size) {
            if (b->size >= size + ARENA_ALIGN) { *out = b->addr; b->addr += size; b->size -= size; }
            else { *out = b->addr; *pp = b->next; free(b); }
            return 0;
        }
    }

    for (struct arena_seg *s = ap->segs; s; s = s->next)
        if (s->size - s->used >= size) { *out = s->base + s->used; s->used += size; return 0; }

    /* Segment sizing (grow-on-demand): start at EXACTLY the request size - no
       speculative over-reservation, so the first fill for a pid is a single
       small hijack, identical exposure to the pre-arena path (proven safe on
       exec-tight games). Grow geometrically as a pid keeps allocating so heavy
       clients still amortize to few hijacks. NEVER a speculative failing probe:
       a single-shot miss retreats to the request size and stops growing this
       pid (a failing probe is a hijack that can catch a lock-holding thread). */
    uint64_t want = ap->next_seg_size;
    if (want < size)        want = size;
    if (want > ARENA_CHUNK) want = ARENA_CHUNK;

    uint64_t seg_size = want;
    uint64_t base = 0;
    int got = 0;
    {
        void *p = (void *)(uintptr_t)0x4000;
        if (sys_proc_alloc(pid, &p, seg_size) == 0) { base = (uint64_t)(uintptr_t)p; got = 1; }
    }
    if (!got) {
        /* Retreat to exactly the request size (the proven-safe, 1-hijack size)
           with one backoff retry for transient contention, and freeze growth
           for this pid so we never repeat a speculative probe. */
        seg_size = size;
        if (do_real_alloc(pid, &base, seg_size, 0x4000) != 0) return -1;
        ap->next_seg_size = size;
    } else {
        ap->next_seg_size = (seg_size < ARENA_CHUNK) ? (seg_size << 1) : ARENA_CHUNK;
    }
    struct arena_seg *s = (struct arena_seg *)malloc(sizeof(*s));
    if (!s) { *out = base; return 0; }
    s->base = base; s->size = seg_size; s->used = size; s->next = ap->segs; ap->segs = s;
    *out = base;
    return 0;
}

static int arena_free(uint32_t pid, uint64_t addr, uint64_t length) {
    struct arena_pid *ap = arena_find(pid);
    if (!ap) return -1;
    int owned = 0;
    for (struct arena_seg *s = ap->segs; s; s = s->next)
        if (addr >= s->base && addr < s->base + s->size) { owned = 1; break; }
    if (!owned) return -1;
    uint64_t size = arena_round(length ? length : ARENA_ALIGN);
    struct arena_blk *b = (struct arena_blk *)malloc(sizeof(*b));
    if (b) { b->addr = addr; b->size = size; b->next = ap->freelist; ap->freelist = b; }
    return 0;
}

int proc_arena_set(int on, char *buf, int bufsz) {
    g_arena_enabled = on ? 1 : 0;
    int n = snprintf(buf, (size_t)bufsz,
        "arena %s (1 hijack per %lluMB segment, sub-alloc 0 hijacks; PLAIN alloc only, hinted passes through)\n",
        g_arena_enabled ? "ENABLED" : "disabled", (unsigned long long)(ARENA_CHUNK >> 20));
    if (n < 0) n = 0;
    if (n > bufsz) n = bufsz;
    klog_puts(buf);
    return n;
}

int proc_remote_alloc(uint32_t pid, uint64_t *out_addr,
                       uint64_t length, uint64_t hint)
{
    mutex_lock();
    int rc;
    if (g_arena_enabled && hint == 0x4000)
        rc = arena_alloc(pid, length, out_addr);
    else
        rc = do_real_alloc(pid, out_addr, length, hint);
    mutex_unlock();
    return rc;
}

int proc_remote_free(uint32_t pid, uint64_t addr, uint64_t length)
{
    mutex_lock();
    int rc;
    if (g_arena_enabled && arena_free(pid, addr, length) == 0)
        rc = 0;
    else
        rc = do_real_free(pid, addr, length);
    mutex_unlock();
    return rc;
}

int proc_remote_call(int pid, struct sys_proc_call_args *args)
{
    mutex_lock();

    int rc = sys_proc_call(pid, args);
    if (rc != 0) {
        debugger_usleep(40000);
        int retries = 6;
        for (;;) {
            rc = sys_proc_call(pid, args);
            if (rc == 0) break;
            debugger_usleep(40000);
            if (--retries == 0) break;
        }
    }

    mutex_unlock();
    return rc;
}
