// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "net.h"
#include "debug.h"
#include "proc.h"
#include "kern_rw_fast.h"
#include "debug_state.h"

struct server_client {
    uint32_t active;
    int      fd;
    uint32_t debugging;
    uint8_t  client_addr[16];
    uint8_t  pad_1c[4];
    uint8_t  dbgctx[0x358];
};

extern struct server_client g_clients[12];
extern void    *curdbgcli;
extern void    *curdbgctx;
extern uint32_t g_debug_attached;
extern void    *g_server_mutex;
extern void    *g_proc_rw_mutex;

#define DEBUG_WAIT_POLL_US 250u
#define DEBUG_WAIT_POLLS   8000u

static int debug_wait4_bounded(int pid, int *out_status) {
    int status = 0;
    for (unsigned int i = 0; i < DEBUG_WAIT_POLLS; i++) {
        int rc = wait4(pid, &status, 1, NULL);
        if (rc > 0) {
            if (out_status) *out_status = status;
            return 1;
        }
        if (rc < 0) return -1;
        sceKernelUsleep(DEBUG_WAIT_POLL_US);
    }
    return 0;
}

struct dbgctx {
    uint32_t pid;
    int      dbgfd;

};

static int g_cached_app_pid = 0;
static int g_cached_app_id  = 0;

#define LWP_CACHE_MAX 512
static int      g_lwp_cache_pid   = 0;
static uint32_t g_lwp_cache_list[LWP_CACHE_MAX];
static int      g_lwp_cache_count = 0;
static uint32_t g_lwp_cache_gen   = 0;

static int get_lwp_list_cached(int pid, uint32_t **out_list, int *out_count) {

    if (pid != g_lwp_cache_pid || g_lwp_cache_count == 0 || g_lwp_cache_gen >= 1024) {
        int num = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
        if (num <= 0 || num > LWP_CACHE_MAX) return -1;
        long r = ptrace_raw(PT_GETLWPLIST, pid, g_lwp_cache_list, num);
        if (r <= 0) return -1;
        g_lwp_cache_count = (int)r;
        g_lwp_cache_pid   = pid;
        g_lwp_cache_gen   = 0;
    } else {
        g_lwp_cache_gen++;
    }
    *out_list  = g_lwp_cache_list;
    *out_count = g_lwp_cache_count;
    return 0;
}

static void lwp_list_cache_flush(void) {
    g_lwp_cache_pid   = 0;
    g_lwp_cache_count = 0;
    g_lwp_cache_gen   = 0;
}

extern intptr_t kern_thread_addr(int pid, int lwpid);

#define RIP_CACHE_N 128
static struct {
    int32_t  pid;
    int32_t  lwpid;
    intptr_t rip_kaddr;
} g_rip_cache[RIP_CACHE_N];
static int      g_rip_cache_next = 0;
static uint32_t g_rip_cache_gen  = 0;

static int kern_get_rip_fast(int pid, int lwpid, uint64_t *out_rip) {

    if (++g_rip_cache_gen >= 1024) {
        for (int i = 0; i < RIP_CACHE_N; i++) g_rip_cache[i].rip_kaddr = 0;
        g_rip_cache_gen = 0;
    }

    for (int i = 0; i < RIP_CACHE_N; i++) {
        if (g_rip_cache[i].pid == pid && g_rip_cache[i].lwpid == lwpid
            && g_rip_cache[i].rip_kaddr) {
            return kernel_copyout_fast(g_rip_cache[i].rip_kaddr, out_rip, 8) < 0 ? 1 : 0;
        }
    }

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread) return 1;
    intptr_t frame_addr;
    if (kernel_copyout_fast(kthread + 0x460, &frame_addr, 8) < 0) return 1;
    int slot = g_rip_cache_next;
    g_rip_cache[slot].pid       = pid;
    g_rip_cache[slot].lwpid     = lwpid;
    g_rip_cache[slot].rip_kaddr = frame_addr + 0xe8;
    g_rip_cache_next = (g_rip_cache_next + 1) % RIP_CACHE_N;
    return kernel_copyout_fast(frame_addr + 0xe8, out_rip, 8) < 0 ? 1 : 0;
}

static int kern_set_rip_fast(int pid, int lwpid, uint64_t new_rip) {
    for (int i = 0; i < RIP_CACHE_N; i++) {
        if (g_rip_cache[i].pid == pid && g_rip_cache[i].lwpid == lwpid
            && g_rip_cache[i].rip_kaddr) {
            return kernel_copyin_fast(&new_rip, g_rip_cache[i].rip_kaddr, 8) < 0 ? 1 : 0;
        }
    }
    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread) return 1;
    intptr_t frame_addr;
    if (kernel_copyout_fast(kthread + 0x460, &frame_addr, 8) < 0) return 1;
    int slot = g_rip_cache_next;
    g_rip_cache[slot].pid       = pid;
    g_rip_cache[slot].lwpid     = lwpid;
    g_rip_cache[slot].rip_kaddr = frame_addr + 0xe8;
    g_rip_cache_next = (g_rip_cache_next + 1) % RIP_CACHE_N;
    return kernel_copyin_fast(&new_rip, frame_addr + 0xe8, 8) < 0 ? 1 : 0;
}

static void rip_cache_flush(void) {
    for (int i = 0; i < RIP_CACHE_N; i++) {
        g_rip_cache[i].pid = 0;
        g_rip_cache[i].lwpid = 0;
        g_rip_cache[i].rip_kaddr = 0;
    }
    g_rip_cache_next = 0;
    g_rip_cache_gen  = 0;
}

void debug_resume_cache_flush(void) {
    g_cached_app_pid = 0;
    g_cached_app_id  = 0;
    lwp_list_cache_flush();
    rip_cache_flush();
}

static int resume_app_via_self_id(int pid) {
    int app_id;
    if (pid != 0 && pid == g_cached_app_pid && g_cached_app_id != 0) {
        app_id = g_cached_app_id;
    } else {
        int rc = _sceApplicationGetAppId(pid, &app_id);
        if (rc != 0) return rc;
        g_cached_app_pid = pid;
        g_cached_app_id  = app_id;
    }
    return sceApplicationContinue(app_id);
}

static inline void resume_app_unelev(struct elev_state *es, int pid) {
    int was_valid = es->valid;
    if (was_valid) elev_restore(es);
    resume_app_via_self_id(pid);
    if (was_valid) (void)elev_save_and_set(es);
}

static inline int authid_bump_safe(uint64_t *out_saved) {
    intptr_t ucred = kernel_get_proc_ucred_fast((pid_t)getpid());
    if (ucred == 0) return -1;
    if (kernel_copyout_fast(ucred + 0x58, out_saved, 8) != 0) return -1;
    if (*out_saved == 0) return -1;
    uint64_t priv_authid = 0x4800000000000006ULL;
    if (kernel_copyin_fast(&priv_authid, ucred + 0x58, 8) != 0) return -1;
    return 0;
}

static inline void authid_restore_safe(uint64_t saved_authid) {
    intptr_t ucred = kernel_get_proc_ucred_fast((pid_t)getpid());
    if (ucred != 0) {
        kernel_copyin_fast(&saved_authid, ucred + 0x58, 8);
    }
}

extern bool fw_uses_kernel_dbreg_path(void);
extern bool is_process_stopped(int pid);
extern bool kern_thread_step_walker(int pid);
extern int  kern_get_dbregs(int pid, int lwpid, void *dbreg_buf);
extern int  kern_set_dbregs(int pid, int lwpid, void *dbreg_buf);
extern int  kern_proc_install_dbregs(int pid, int lwpid, void *fpu_buf);
extern int  kern_get_proc_info_by_pid(int pid, int lwpid, void *regs_buf);
extern int  kern_apply_thread_dbgctx(int pid, int lwpid, void *regs_buf);
extern int  kern_get_lwp_full_state(int pid, int lwpid, void *regs, void *dbreg, void *fpu);
extern int  kern_get_fpregs(int pid, int lwpid, void *fpu_buf);
extern int  kern_set_fpregs(int pid, int lwpid, const void *fpu_buf);
extern int  kern_get_fsgsbase(int pid, int lwpid, void *out16);
extern int  kern_set_fsgsbase(int pid, int lwpid, const void *in16);
extern void kern_thread_cache_flush(void);

#define REG_BLOB_SIZE      0xB0
#define FPREG_BLOB_SIZE    0x340
#define DBREG_BLOB_SIZE    0x80
#define FSGSBASE_BLOB_SIZE 0x10

struct cmd_debug_lwp_packet {
    uint32_t lwpid;
} __attribute__((packed));

struct cmd_debug_setreg_packet {
    uint32_t lwpid;
    uint32_t length;
} __attribute__((packed));

#define DBGCTX() ((struct dbgctx *)curdbgctx)

int connect_debugger(struct dbgctx *ctx, void *client_sockaddr_in) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(755);

    addr.sin_addr.s_addr = *(uint32_t *)((uint8_t *)client_sockaddr_in + 4);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    ctx->dbgfd = sock;
    if (sock <= 0) return 1;

    extern void configure_socket(int fd);
    configure_socket(sock);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        ctx->dbgfd = -1;
        return 1;
    }
    return 0;
}

uint32_t g_stepping_lwpid = 0;

#define DBG_STORM_FATAL_SIGS(sig) \
    ((sig) == 11  || (sig) == 7  || (sig) == 4  || (sig) == 8 )
#define DBG_STORM_LIMIT 32
static uint32_t g_storm_lwpid  = 0;
static uint64_t g_storm_rip    = 0;
static uint8_t  g_storm_sig    = 0;
static uint32_t g_storm_count  = 0;

extern int sys_proc_vm_map(uint32_t pid, void **out_maps, int *out_count);
extern int gettimeofday(struct timeval *tp, void *tzp);

#define INT3_REWIND_MAX 16
#define DBG_BP_SLOT_SIZE 0x18
static uint64_t g_recently_disabled_bps[INT3_REWIND_MAX];
static int      g_recently_disabled_count = 0;

static int int3_scan_stuck(int pid, const uint64_t *bp_addrs, int n_bps,
                           int *out_lwpids, int out_cap, int *out_n) {
    if (out_n) *out_n = 0;
    int stuck = 0;
    if (n_bps <= 0) return 0;

    int numlwps = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
    if (numlwps <= 0) return 0;

    int *lwpids = (int *)net_alloc_buffer((unsigned long)(numlwps * 4));
    if (!lwpids) return 0;

    long lr = ptrace_raw(PT_GETLWPLIST, pid, lwpids, numlwps);
    if (lr > 0) {
        uint8_t regs_buf[176];
        for (int i = 0; i < numlwps; i++) {
            errno = 0;
            if (ptrace_raw(PT_GETREGS, lwpids[i], regs_buf, 0) != 0) continue;
            uint64_t rip = *(uint64_t *)(regs_buf + 0x88);
            for (int b = 0; b < n_bps; b++) {
                uint64_t a = bp_addrs[b];
                int hit = 0;
                if (rip == a + 1) {

                    uint8_t li_buf[160];
                    if (ptrace_raw(PT_LWPINFO, lwpids[i], li_buf, 160) != 0) {
                        continue;
                    }
                    if (*(int32_t *)(li_buf + 0x04) != 1 ) continue;
                    if (*(int32_t *)(li_buf + 0x30) != 5 )        continue;
                    if (*(int32_t *)(li_buf + 0x38) != 1 )     continue;
                    *(uint64_t *)(regs_buf + 0x88) = a;
                    ptrace_raw(PT_SETREGS, lwpids[i], regs_buf, 0);
                    hit = 1;
                } else if (rip == a) {
                    hit = 1;
                } else if (rip > a + 1 && rip < a + 16) {
                    hit = 1;
                }
                if (hit) {
                    if (out_lwpids && stuck < out_cap) out_lwpids[stuck] = lwpids[i];
                    stuck++;
                    break;
                }
            }
        }
    }
    free(lwpids);
    if (out_n) *out_n = (stuck < out_cap) ? stuck : out_cap;
    return stuck;
}

static int int3_lwp_stopped(int lwp) {
    uint8_t rb[176];
    errno = 0;
    if (ptrace_raw(PT_GETREGS, lwp, rb, 0) == 0) return 1;
    return (errno == 16) ? -1 : 0;
}

static void int3_resume_lwps(int pid, const int *lwpids, int n) {
    for (int i = 0; i < n && i < 256; i++) {
        int lw = lwpids[i];
        if (int3_lwp_stopped(lw) == 0) continue;
        for (int tries = 0; tries < 12; tries++) {
            errno = 0;
            ptrace_raw(PT_CONTINUE, lw, (void *)1, 0);
            int e1 = errno;
            if (int3_lwp_stopped(lw) == 0) break;
            errno = 0;
            ptrace_raw(PT_CONTINUE, pid, (void *)1, 0);
            int e2 = errno;
            if (int3_lwp_stopped(lw) == 0) break;
            sceKernelUsleep((e1 == 16 || e2 == 16) ? 1500 : 400);
        }
    }
}

static void int3_iterative_sweep(int pid, const uint64_t *bp_addrs, int n_bps) {
    if (n_bps <= 0) return;
    for (int round = 0; round < 4; round++) {
        int lw[INT3_REWIND_MAX]; int n = 0;
        int stuck = int3_scan_stuck(pid, bp_addrs, n_bps, lw, INT3_REWIND_MAX, &n);
        if (stuck == 0) break;
        int3_resume_lwps(pid, lw, n);
        sceKernelUsleep(5000);
    }
}

static void debug_clear_breakpoint_slots(void *svc) {
    if (!svc) return;

    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        char *bp_entry = (char *)svc + i * DBG_BP_SLOT_SIZE;
        *(uint32_t *)(bp_entry + 0x08) = 0;
        *(uint64_t *)(bp_entry + 0x10) = 0;
    }
}

static void debug_clear_watchpoint_shadow(void *svc) {
    if (!svc) return;

    memset((char *)svc + 0x2D8, 0, DBREG_BLOB_SIZE);
}

void debug_full_teardown(void *svc) {
    if (!g_debug_attached) {
        debug_clear_breakpoint_slots(svc);
        debug_clear_watchpoint_shadow(svc);
        g_debug_pending_wait_valid = 0;
        g_debug_pending_wait_pid = 0;
        g_debug_pending_wait_status = 0;
        g_debug_phase = DEBUG_PHASE_DETACHED;
        return;
    }

    g_debug_phase = DEBUG_PHASE_DETACHING;

    g_recently_disabled_count = 0;

    debug_resume_cache_flush();
    kern_proc_cache_flush();
    kern_thread_cache_flush();

    struct elev_state es;
    int es_active = (elev_save_and_set(&es) == 0);

    void *old_cli = curdbgcli;
    curdbgcli = NULL;
    if (old_cli) {
        *(uint32_t *)((char *)old_cli + 8) = 0;
    }
    curdbgctx = NULL;
    g_debug_attached = 0;

    uint32_t prev_state = g_stopgo_mode;
    g_stopgo_resume_signal = 0xFFFFFFFFu;
    g_stopgo_resume_pid  = 0;
    if (prev_state == 2) {
        g_stopgo_mode = 0;
        g_stopgo_last_signal = 0xFFFFFFFFu;
        g_stopgo_target_pid  = 0;
    }

    int      pid   = svc ? *(int *)svc : 0;
    uint32_t dbgfd = svc ? *(uint32_t *)((char *)svc + 4) : 0;

    int   vm_count = 0;
    void *vm_maps  = NULL;
    int   alive_rc = sys_proc_vm_map((uint32_t)pid, &vm_maps, &vm_count);
    if (alive_rc != 0) {
        if (vm_maps) free(vm_maps);
        ptrace_raw(PT_DETACH, pid, NULL, 0);
        goto close_socket_and_unlock;
    }
    if (vm_maps) free(vm_maps);

    uint64_t teardown_bp_addrs[INT3_REWIND_MAX];
    int teardown_n_bps = 0;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        char *bp_entry = (char *)svc + i * DBG_BP_SLOT_SIZE;
        uint32_t enabled = *(uint32_t *)(bp_entry + 0x08);
        uint64_t address = *(uint64_t *)(bp_entry + 0x10);
        if (enabled && address) {
            proc_write_mem((uint32_t)pid, address, 1,
                           bp_entry + DBG_BP_SLOT_SIZE);
            if (teardown_n_bps < INT3_REWIND_MAX) {
                teardown_bp_addrs[teardown_n_bps++] = address;
            }
        }
    }

    int3_iterative_sweep(pid, teardown_bp_addrs, teardown_n_bps);

    char dr_buf[0x100];
    memset(dr_buf, 0, sizeof(dr_buf));
    ptrace_raw(PT_GETDBREGS, pid, dr_buf, 0);

    uint8_t dr7_low = (uint8_t)dr_buf[0x38];
    int     have_active_dr =
        (dr7_low & 0x03) || (dr7_low & 0x0C) ||
        (dr7_low & 0x30) || (dr7_low & 0xC0);

    int *lwpids = NULL;
    int  count  = 0;
    int  we_stopped = 0;

    if (!have_active_dr) {
        int rc = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
        if (rc == -1) {
            if (errno != 16 ) {
                goto free_and_detach;
            }
            if (kill(pid, 17) != 0
                || debug_wait4_bounded(pid, NULL) != 1) {
                goto free_and_detach;
            }
            we_stopped = 1;
            ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
        }
        goto free_and_detach;
    }

    int rc = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
    if (rc == -1) {
        if (errno != 16) {
            goto free_and_detach;
        }
        if (kill(pid, 17) != 0
            || debug_wait4_bounded(pid, NULL) != 1) {
            goto free_and_detach;
        }
        we_stopped = 1;
        rc    = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
        count = rc;
        lwpids = (int *)net_alloc_buffer((unsigned long)(count * 4));
        if (!lwpids) {
            goto free_and_detach;
        }
        if (ptrace_raw(PT_GETLWPLIST, pid, lwpids, count) == -1) {
            goto free_and_detach;
        }
    } else {
        count = rc;
        lwpids = (int *)net_alloc_buffer((unsigned long)(count * 4));
        if (!lwpids) {
            goto free_and_detach;
        }
        if (ptrace_raw(PT_GETLWPLIST, pid, lwpids, count) == -1) {
            goto free_and_detach;
        }
    }

    if (count == 0) {
        goto free_and_detach;
    }

    memset(dr_buf, 0, sizeof(dr_buf));
    bool use_kernel_path = fw_uses_kernel_dbreg_path();
    for (int i = 0; i < count; i++) {
        int lwpid = lwpids[i];
        if (use_kernel_path) {
            if (kern_set_dbregs(pid, lwpid, dr_buf) != 0) {
                ptrace_raw(PT_SETDBREGS, lwpid, dr_buf, 0);
            }
        } else {
            ptrace_raw(PT_SETDBREGS, lwpid, dr_buf, 0);
        }
    }

free_and_detach:
    if (lwpids) free(lwpids);
    if (we_stopped) {
        resume_app_unelev(&es, pid);
    }
    ptrace_raw(PT_DETACH, pid, NULL, 0);

close_socket_and_unlock:
    if (dbgfd > 0) {
        close((int)dbgfd);
    }

    /* A command connection can attach again without being recreated. Clear
       every slot after any live-target restores, including the dead-target
       liveness-failure path, so a later arm cannot match stale state. */
    debug_clear_breakpoint_slots(svc);
    debug_clear_watchpoint_shadow(svc);

    g_debug_pending_wait_valid = 0;
    g_debug_pending_wait_pid = 0;
    g_debug_pending_wait_status = 0;
    g_debug_phase = DEBUG_PHASE_DETACHED;
    if (es_active) elev_restore(&es);
}

static const uint32_t k_stopgo_signal_table[3] = { 19u , 17u , 9u  };

int debug_stopgo_handle(int pid, char action) {
    scePthreadMutexLock(&g_server_mutex);
    g_stopgo_target_pid = (uint32_t)pid;

    if (g_debug_attached) {
        if (action == 0) {
            if (g_debug_phase == DEBUG_PHASE_RUNNING) {
                scePthreadMutexUnlock(&g_server_mutex);
                return 0;
            }
            if (g_debug_phase != DEBUG_PHASE_EVENT_STOPPED) {
                scePthreadMutexUnlock(&g_server_mutex);
                return -1;
            }
            g_debug_phase = DEBUG_PHASE_RESUMING;
            g_stopgo_resume_signal = 0;
            g_stopgo_resume_pid  = (uint32_t)pid;
            g_stopgo_last_signal = 0;
            g_stopgo_mode = 2;
        } else if (action == 1) {
            if (g_debug_phase == DEBUG_PHASE_EVENT_STOPPED) {
                scePthreadMutexUnlock(&g_server_mutex);
                return 0;
            }
            if (g_debug_phase != DEBUG_PHASE_RUNNING) {
                scePthreadMutexUnlock(&g_server_mutex);
                return -1;
            }
            int stop_status = 0;
            if (kill(pid, 0x11) != 0
                || debug_wait4_bounded(pid, &stop_status) != 1) {
                g_debug_phase = DEBUG_PHASE_BROKEN;
                scePthreadMutexUnlock(&g_server_mutex);
                return -1;
            }
            if (((stop_status >> 8) & 0xFF) != 0x11) {
                g_debug_pending_wait_pid = (uint32_t)pid;
                g_debug_pending_wait_status = stop_status;
                g_debug_pending_wait_valid = 1;
                g_debug_phase = DEBUG_PHASE_EVENT_PENDING;
                scePthreadMutexUnlock(&g_server_mutex);
                return 0;
            }
            g_stopgo_last_signal = 0x11;
            g_debug_phase = DEBUG_PHASE_EVENT_STOPPED;
            g_stopgo_mode = 2;
        } else if (action == 2) {
            g_debug_phase = DEBUG_PHASE_DETACHING;
            g_stopgo_resume_signal = 9;
            g_stopgo_resume_pid  = (uint32_t)pid;
            g_stopgo_last_signal = 9;
            g_stopgo_mode = 2;
        }
    } else {
        if ((unsigned char)action <= 2) {
            uint32_t sig = k_stopgo_signal_table[(unsigned char)action];
            g_stopgo_mode = 1;
            g_stopgo_last_signal = sig;
            if (kill(pid, (int)sig) != 0 || debug_wait4_bounded(pid, NULL) != 1) {
                scePthreadMutexUnlock(&g_server_mutex);
                return -1;
            }
            if (action == 0 && g_debug_attached) {
                resume_app_via_self_id((int)g_stopgo_resume_pid);
            }
        } else {
            if (kill(pid, 0) != 0 || debug_wait4_bounded(pid, NULL) != 1) {
                scePthreadMutexUnlock(&g_server_mutex);
                return -1;
            }
        }
    }

    scePthreadMutexUnlock(&g_server_mutex);
    return 0;
}

int debug_process_stop_handle(int fd, struct cmd_packet *packet) {
    void *data = packet->data;
    if (!data) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    unsigned char action = ((unsigned char *)data)[4];
    if (action > 2) { net_send_int32(fd, CMD_ERROR); return 1; }

    int pid = *(int *)data;
    if (pid == 0)   { net_send_int32(fd, CMD_ERROR); return 1; }

    if (debug_stopgo_handle(pid, (char)action) != 0) {
        net_send_int32(fd, CMD_ERROR);
        return 0;
    }
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

extern long ptrace_raw(int op, int pid, void *addr, int data);

int debug_attach_handle(int fd, struct cmd_packet *packet) {
    if (g_debug_attached || g_debug_phase != DEBUG_PHASE_DETACHED) {
        net_send_int32(fd, CMD_ALREADY_DEBUG);
        return 1;
    }

    struct cmd_debug_attach_packet *ap =
        (struct cmd_debug_attach_packet *)packet->data;
    if (!ap) {
        curdbgcli = NULL;
        curdbgctx = NULL;
        net_send_int32(fd, CMD_DATA_NULL);
        return 1;
    }

    g_debug_phase = DEBUG_PHASE_ATTACHING;
    DBGCTX()->pid = ap->pid;
    DBGCTX()->dbgfd = -1;

    struct elev_state es;
    if (elev_save_and_set(&es) != 0) {
        g_debug_phase = DEBUG_PHASE_DETACHED;
        curdbgcli = NULL;
        curdbgctx = NULL;
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    if (ptrace_raw(PT_ATTACH, ap->pid, NULL, 0) == -1) {
        elev_restore(&es);
        g_debug_phase = DEBUG_PHASE_DETACHED;
        curdbgcli = NULL;
        curdbgctx = NULL;
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    elev_restore(&es);

    /* From this point on free_client must run the full remote teardown on any
       error. Claim the lifecycle only after PT_ATTACH has actually succeeded. */
    g_debug_attached = 1;
    *(uint32_t *)((char *)curdbgcli + 8) = 1;

    int wait_status = 0;
    if (debug_wait4_bounded(ap->pid, &wait_status) != 1) {
        g_debug_phase = DEBUG_PHASE_BROKEN;
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    resume_app_via_self_id(ap->pid);

    if (elev_save_and_set(&es) != 0) {
        g_debug_phase = DEBUG_PHASE_BROKEN;
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }
    if (ptrace_raw(PT_CONTINUE, ap->pid, (void *)1, 0) != 0) {
        elev_restore(&es);
        g_debug_phase = DEBUG_PHASE_BROKEN;
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    elev_restore(&es);

    void *evt_client_sockaddr = (char *)curdbgcli + 0x0C;
    if (connect_debugger(DBGCTX(), evt_client_sockaddr) != 0) {
        g_debug_phase = DEBUG_PHASE_BROKEN;
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    g_debug_phase = DEBUG_PHASE_RUNNING;
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int debug_detach_handle(int fd, struct cmd_packet *packet) {
    (void)packet;
    debug_full_teardown(curdbgctx);
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int debug_set_breakpoint_handle(int fd, struct cmd_packet *packet) {
    if (!g_debug_attached) { net_send_int32(fd, CMD_ERROR); return 1; }
    int pid = DBGCTX()->pid;
    if (pid == 0) { net_send_int32(fd, CMD_ERROR); return 1; }

    struct cmd_debug_breakpt_packet *bp =
        (struct cmd_debug_breakpt_packet *)packet->data;
    if (!bp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    if (bp->index > MAX_BREAKPOINTS - 1) {
        net_send_int32(fd, CMD_INVALID_INDEX);
        return 1;
    }

    char *bp_entry  = (char *)curdbgctx + bp->index * DBG_BP_SLOT_SIZE;
    char *saved_byte_slot = bp_entry + DBG_BP_SLOT_SIZE;

    if (bp->enabled) {
        if (bp->address == 0) {
            net_send_int32(fd, CMD_ERROR);
            return 0;
        }

        uint32_t was_enabled = *(uint32_t *)(bp_entry + 0x08);
        uint64_t old_address = *(uint64_t *)(bp_entry + 0x10);

        /* Repeating the exact same arm is idempotent. Re-reading here would
           save the already-patched 0xCC and destroy the restore byte. Moving
           an enabled slot must be expressed as a disarm followed by an arm. */
        if (was_enabled) {
            if (old_address == bp->address) {
                net_send_int32(fd, CMD_SUCCESS);
                return 0;
            }
            net_send_int32(fd, CMD_ERROR);
            return 0;
        }

        /* Debug commands are serialized by handle_client's debugger locks.
           Enforce one physical INT3 owner per address while those locks are
           held so no second slot can save 0xCC as its original byte. */
        for (int i = 0; i < MAX_BREAKPOINTS; i++) {
            if (i == (int)bp->index) continue;
            char *other = (char *)curdbgctx + i * DBG_BP_SLOT_SIZE;
            if (*(uint32_t *)(other + 0x08)
                && *(uint64_t *)(other + 0x10) == bp->address) {
                net_send_int32(fd, CMD_ERROR);
                return 0;
            }
        }

        *(uint32_t *)(bp_entry + 0x08) = 1;
        *(uint64_t *)(bp_entry + 0x10) = bp->address;

        sys_proc_rw_w0((uint64_t)pid, bp->address, 1, saved_byte_slot, 0);

        unsigned char int3 = 0xCC;
        proc_write_mem((uint32_t)pid, bp->address, 1, &int3);
    } else {

        uint32_t was_enabled = *(uint32_t *)(bp_entry + 0x08);
        uint64_t bp_addr     = *(uint64_t *)(bp_entry + 0x10);

        if (was_enabled && bp_addr) {
            struct elev_state es;
            int es_active = (elev_save_and_set(&es) == 0);

            int stuck_lw[INT3_REWIND_MAX]; int stuck_n = 0;
            int stuck = int3_scan_stuck(pid, &bp_addr, 1, stuck_lw, INT3_REWIND_MAX, &stuck_n);

            proc_write_mem((uint32_t)pid, bp_addr, 1, saved_byte_slot);

            if (stuck > 0) {
                int3_resume_lwps(pid, stuck_lw, stuck_n);
            }
            ptrace_raw(PT_CONTINUE, pid, (void *)1, 0);

            if (es_active) elev_restore(&es);

            if (g_recently_disabled_count < INT3_REWIND_MAX) {
                g_recently_disabled_bps[g_recently_disabled_count++] = bp_addr;
            }
        }

        *(uint32_t *)(bp_entry + 0x08) = 0;
        *(uint64_t *)(bp_entry + 0x10) = 0;
    }

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int debug_set_watchpoint_handle(int fd, struct cmd_packet *packet) {
    if (!g_debug_attached) { net_send_int32(fd, CMD_ERROR); return 1; }
    int pid = DBGCTX()->pid;
    if (pid == 0) { net_send_int32(fd, CMD_ERROR); return 1; }

    struct cmd_debug_watchpt_packet *wp =
        (struct cmd_debug_watchpt_packet *)packet->data;
    if (!wp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }
    if (wp->index > 3) { net_send_int32(fd, CMD_INVALID_INDEX); return 1; }

    struct elev_state es;
    if (elev_save_and_set(&es) != 0) {
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    int  count;
    int *lwpids = NULL;
    int  we_stopped;
    int  ret_rc;

    int rc = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
    if (rc != -1) {
        count = rc; we_stopped = 0;
        lwpids = (int *)net_alloc_buffer((unsigned long)(count * 4));
        if (!lwpids) goto wp_err_no_resume;
        if (ptrace_raw(PT_GETLWPLIST, pid, lwpids, count) == -1) {
            free(lwpids); goto wp_err_no_resume;
        }
    } else {
        if (errno != 16 ) goto wp_err_no_resume;
        if (kill(pid, 17) != 0
            || debug_wait4_bounded(pid, NULL) != 1) {
            g_debug_phase = DEBUG_PHASE_BROKEN;
            goto wp_err_no_resume;
        }
        count = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
        we_stopped = 1;
        lwpids = (int *)net_alloc_buffer((unsigned long)(count * 4));
        if (!lwpids) goto wp_resume_and_err;
        if (ptrace_raw(PT_GETLWPLIST, pid, lwpids, count) == -1) {
            free(lwpids); goto wp_resume_and_err;
        }
    }

    char     *ctx     = (char *)curdbgctx;
    uint64_t *dr_addr = (uint64_t *)(ctx + 0x2D8);
    uint64_t *dr7     = (uint64_t *)(ctx + 0x310);

    int idx = (int)wp->index;
    int cl1 = idx * 2;
    int cl2 = idx * 4 + 16;

    uint64_t mask = ((uint64_t)0xFu << cl2)
                  | (uint64_t)(int64_t)(int32_t)(3 << cl1);
    *dr7 &= ~mask;

    if (wp->enabled) {
        dr_addr[idx] = wp->address;
        uint64_t low_bits  = (uint64_t)(int64_t)(int32_t)(3 << cl1);
        uint64_t high_bits = (((uint64_t)wp->length << 2) | (uint64_t)wp->breaktype) << cl2;
        *dr7 |= low_bits | high_bits;
    } else {
        dr_addr[idx] = 0;
    }

    void *dr_block = (void *)(ctx + 0x2D8);
    for (int i = 0; i < count; i++) {
        if (ptrace_raw(PT_SETDBREGS, lwpids[i], dr_block, 0) == -1) {
            if (errno != 0) {
                free(lwpids);
                if (we_stopped) goto wp_resume_and_err;
                goto wp_err_no_resume;
            }
        }
    }

    if (we_stopped) {
        resume_app_unelev(&es, pid);
        ptrace_raw(PT_CONTINUE, pid, (void *)1, 0);
    }
    net_send_int32(fd, CMD_SUCCESS);
    free(lwpids);
    ret_rc = 0;
    goto wp_done;

wp_resume_and_err:
    resume_app_unelev(&es, pid);
    ptrace_raw(PT_CONTINUE, pid, (void *)1, 0);
wp_err_no_resume:
    net_send_int32(fd, CMD_ERROR);
    ret_rc = 1;
wp_done:
    elev_restore(&es);
    return ret_rc;
}

int debug_get_thread_list_handle(int fd, struct cmd_packet *packet) {
    (void)packet;
    if (!g_debug_attached) { net_send_int32(fd, CMD_ERROR); return 1; }
    int pid = DBGCTX()->pid;
    if (pid == 0) { net_send_int32(fd, CMD_ERROR); return 1; }

    int count = (int)ptrace_elev(PT_GETNUMLWPS, pid, NULL, 0);
    int we_stopped = 0;

    if (count == -1) {
        if (errno != 16 ) { net_send_int32(fd, CMD_ERROR); return 1; }
        if (kill(pid, 17) != 0
            || debug_wait4_bounded(pid, NULL) != 1) {
            g_debug_phase = DEBUG_PHASE_BROKEN;
            net_send_int32(fd, CMD_ERROR);
            return 1;
        }
        count = (int)ptrace_elev(PT_GETNUMLWPS, pid, NULL, 0);
        we_stopped = 1;
    }

    int   size = count * 4;
    int  *buf  = (int *)net_alloc_buffer((unsigned long)size);
    if (!buf) goto err;
    if (ptrace_elev(PT_GETLWPLIST, pid, buf, count) == -1) goto err;

    if (we_stopped) {
        resume_app_via_self_id(pid);
        ptrace_elev(PT_CONTINUE, pid, (void *)1, 0);
    }

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, &count, 4);
    net_send_all(fd, buf, size);
    free(buf);
    return 0;

err:
    if (we_stopped) ptrace_elev(PT_CONTINUE, pid, (void *)1, 0);
    if (buf) free(buf);
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_suspend_thread_handle(int fd, struct cmd_packet *packet) {
    void *data = packet->data;
    if (DBGCTX()->pid == 0) { net_send_int32(fd, CMD_ERROR);     return 1; }
    if (!data)              { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    if (ptrace_elev(PT_SUSPEND, *(int *)data, NULL, 0) == -1) {
        net_send_int32(fd, CMD_ERROR);
        return 0;
    }
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int debug_resume_thread_handle(int fd, struct cmd_packet *packet) {
    void *data = packet->data;
    if (DBGCTX()->pid == 0) { net_send_int32(fd, CMD_ERROR);     return 1; }
    if (!data)              { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    if (ptrace_elev(PT_RESUME, *(int *)data, NULL, 0) == -1) {
        net_send_int32(fd, CMD_ERROR);
        return 0;
    }
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int debug_getregs_handle(int fd, struct cmd_packet *packet) {
    char buf[REG_BLOB_SIZE];
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_lwp_packet *gp = (struct cmd_debug_lwp_packet *)packet->data;
    if (!gp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    memset(buf, 0, REG_BLOB_SIZE);
    if (ptrace_elev(PT_GETREGS, gp->lwpid, buf, 0) == -1 && errno != 0) goto err;

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, buf, REG_BLOB_SIZE);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_setregs_handle(int fd, struct cmd_packet *packet) {
    char buf[REG_BLOB_SIZE];
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_setreg_packet *sp = (struct cmd_debug_setreg_packet *)packet->data;
    if (!sp) goto err;

    net_send_int32(fd, CMD_SUCCESS);
    net_recv_all(fd, buf, sp->length, 1);

    if (ptrace_elev(PT_SETREGS, pid, buf, 0) == -1 && errno != 0) goto err;

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_getfpregs_handle(int fd, struct cmd_packet *packet) {
    char buf[FPREG_BLOB_SIZE] __attribute__((aligned(64)));
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_lwp_packet *gp = (struct cmd_debug_lwp_packet *)packet->data;
    if (!gp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    memset(buf, 0, FPREG_BLOB_SIZE);

    if (kern_get_fpregs(pid, gp->lwpid, buf) != 0) {
        if (ptrace_elev(PT_GETFPREGS, gp->lwpid, buf, 0) == -1 && errno != 0) goto err;
    }

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, buf, FPREG_BLOB_SIZE);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_setfpregs_handle(int fd, struct cmd_packet *packet) {
    char buf[FPREG_BLOB_SIZE] __attribute__((aligned(64)));
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_setreg_packet *sp = (struct cmd_debug_setreg_packet *)packet->data;
    if (!sp) goto err;
    if (sp->length > FPREG_BLOB_SIZE) goto err;

    memset(buf, 0, FPREG_BLOB_SIZE);
    net_send_int32(fd, CMD_SUCCESS);
    if (net_recv_all(fd, buf, sp->length, 1) < 0) goto err;

    int applied = 0;
    if (sp->length == FPREG_BLOB_SIZE)
        applied = (kern_set_fpregs(pid, sp->lwpid, buf) == 0);
    if (!applied) {
        if (ptrace_elev(PT_SETFPREGS, pid, buf, 0) == -1 && errno != 0) goto err;
    }

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_getdbregs_handle(int fd, struct cmd_packet *packet) {
    char buf[DBREG_BLOB_SIZE];
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_lwp_packet *gp = (struct cmd_debug_lwp_packet *)packet->data;
    if (!gp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    int we_stopped = 0;
    if (is_process_stopped(pid) == 0) {
        if (kill(pid, 17) != 0
            || debug_wait4_bounded(pid, NULL) != 1) {
            g_debug_phase = DEBUG_PHASE_BROKEN;
            goto err;
        }
        we_stopped = 1;
    }

    memset(buf, 0, DBREG_BLOB_SIZE);

    if (fw_uses_kernel_dbreg_path()) {
        if (kern_get_dbregs(pid, gp->lwpid, buf) != 0) goto err;
    } else {
        if (ptrace_elev(PT_GETDBREGS, gp->lwpid, buf, 0) == -1 && errno != 0) goto err;
    }

    if (we_stopped) {
        resume_app_via_self_id(pid);
        ptrace_elev(PT_CONTINUE, pid, (void *)1, 0);
    }

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, buf, DBREG_BLOB_SIZE);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_setdbregs_handle(int fd, struct cmd_packet *packet) {
    char buf[DBREG_BLOB_SIZE];
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_setreg_packet *sp = (struct cmd_debug_setreg_packet *)packet->data;
    if (!sp) goto err;

    net_send_int32(fd, CMD_SUCCESS);
    net_recv_all(fd, buf, sp->length, 1);

    if (ptrace_elev(PT_CONTINUE, pid, (void *)1, 0) != 0
        || kill(pid, 17) != 0
        || debug_wait4_bounded(pid, NULL) != 1) {
        g_debug_phase = DEBUG_PHASE_BROKEN;
        goto err;
    }

    if (ptrace_elev(PT_SETDBREGS, sp->lwpid, buf, 0) == -1 && errno != 0) goto err;

    resume_app_via_self_id(pid);
    ptrace_elev(PT_CONTINUE, pid, (void *)1, 0);

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_getfsgsbase_handle(int fd, struct cmd_packet *packet) {
    char buf[FSGSBASE_BLOB_SIZE];
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_lwp_packet *gp = (struct cmd_debug_lwp_packet *)packet->data;
    if (!gp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    memset(buf, 0, FSGSBASE_BLOB_SIZE);

    if (kern_get_fsgsbase(pid, gp->lwpid, buf) != 0) goto err;

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, buf, FSGSBASE_BLOB_SIZE);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_setfsgsbase_handle(int fd, struct cmd_packet *packet) {
    char buf[FSGSBASE_BLOB_SIZE];
    if (!g_debug_attached) goto err;
    int pid = DBGCTX()->pid;
    if (pid == 0) goto err;

    struct cmd_debug_setreg_packet *sp = (struct cmd_debug_setreg_packet *)packet->data;
    if (!sp) goto err;
    if (sp->length != FSGSBASE_BLOB_SIZE) goto err;

    memset(buf, 0, FSGSBASE_BLOB_SIZE);
    net_send_int32(fd, CMD_SUCCESS);
    if (net_recv_all(fd, buf, sp->length, 1) < 0) goto err;

    if (kern_set_fsgsbase(pid, sp->lwpid, buf) != 0) goto err;

    net_send_int32(fd, CMD_SUCCESS);
    return 0;
err:
    net_send_int32(fd, CMD_ERROR);
    return 1;
}

int debug_continue_handle(int fd, struct cmd_packet *packet) {
    int pid = DBGCTX()->pid;
    if (pid == 0) { net_send_int32(fd, CMD_ERROR); return 1; }

    void *data = packet->data;
    if (!data) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    if (debug_stopgo_handle(pid, *(char *)data) != 0) {
        net_send_int32(fd, CMD_ERROR);
        return 0;
    }
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

struct dbg_thrinfo_response {
    uint32_t lwpid;
    uint32_t priority;
    char     tdname[32];
} __attribute__((packed));

static int kern_get_thread_info(int pid, uint32_t *thrinfo_out)
{
    if (pid == 0)        return 1;
    if (!thrinfo_out)    return 1;

    intptr_t kproc = kernel_get_proc_fast(pid);
    if (!kproc)          return 1;

    uint8_t  chain_hdr[0x30];
    if (kernel_copyout_fast(kproc + 0x10, chain_hdr, 0x30) != 0) return 1;

    uint64_t kthread = *(uint64_t *)chain_hdr;
    if (!kthread)        return 1;

    uint8_t tbuf[0x680];
    for (;;) {
        if (kernel_copyout_fast((intptr_t)kthread, tbuf, 0x680) != 0) return 1;
        if (*(uint32_t *)(tbuf + 0x9c) == thrinfo_out[0]) {
            thrinfo_out[1] = *(uint16_t *)(tbuf + 0x3c0);
            memcpy((char *)thrinfo_out + 8, tbuf + 0x294, 0x20);
            return 0;
        }
        kthread = *(uint64_t *)(tbuf + 0x10);
        if (!kthread)    return 1;
    }
}

int debug_thread_info_handle(int fd, struct cmd_packet *packet) {
    if (!g_debug_attached) { net_send_int32(fd, CMD_ERROR); return 1; }
    int pid = DBGCTX()->pid;
    if (pid == 0) { net_send_int32(fd, CMD_ERROR); return 1; }

    struct cmd_debug_lwp_packet *gp = (struct cmd_debug_lwp_packet *)packet->data;
    if (!gp) { net_send_int32(fd, CMD_DATA_NULL); return 1; }

    uint32_t thrinfo[10];
    memset(thrinfo, 0, sizeof(thrinfo));
    thrinfo[0] = gp->lwpid;
    if (kern_get_thread_info(pid, thrinfo) != 0) {
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }

    struct dbg_thrinfo_response resp;
    memset(&resp, 0, sizeof(resp));
    resp.lwpid    = thrinfo[0];
    resp.priority = thrinfo[1];
    memcpy(resp.tdname, (char *)thrinfo + 8, 32);
    resp.tdname[31] = 0;

    net_send_int32(fd, CMD_SUCCESS);
    net_send_all(fd, &resp, sizeof(resp));
    return 0;
}

int debug_step_handle(int fd, struct cmd_packet *packet) {
    (void)packet;
    if (!g_debug_attached) { net_send_int32(fd, CMD_ERROR); return 1; }
    int pid = DBGCTX()->pid;
    if (pid == 0) {
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }
    if (ptrace_elev(PT_STEP, pid, (void *)1, 0) != 0) {
        net_send_int32(fd, CMD_ERROR);
        return 1;
    }
    g_debug_phase = DEBUG_PHASE_STEPPING;
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

int debug_step_thread_handle(int fd, struct cmd_packet *packet) {
    if (!g_debug_attached) { net_send_int32(fd, CMD_ERROR); return 1; }
    int pid = DBGCTX()->pid;
    if (pid == 0) { net_send_int32(fd, CMD_ERROR); return 1; }

    struct cmd_debug_lwp_packet *gp = (struct cmd_debug_lwp_packet *)packet->data;

    long rc;
    if (gp) {
        scePthreadMutexLock(&g_server_mutex);

        int drain_status = 0;
        int drain_count = 0;
        while (drain_count < 64 && wait4(pid, &drain_status, 1, NULL) > 0) {
            drain_count++;
        }

        g_stepping_lwpid = gp->lwpid;
        rc = ptrace_elev(PT_STEP, (int)gp->lwpid, (void *)1, 0);
        scePthreadMutexUnlock(&g_server_mutex);
    } else {
        rc = ptrace_elev(PT_STEP, pid, (void *)1, 0);
    }

    if (rc != 0) { net_send_int32(fd, CMD_ERROR); return 1; }
    g_debug_phase = DEBUG_PHASE_STEPPING;
    net_send_int32(fd, CMD_SUCCESS);
    return 0;
}

static void debug_handle_breakpoint_resume(void) {
    if (!g_debug_attached) return;
    int sig = (int)g_stopgo_resume_signal;
    if (sig == -1) return;

    int pid = (int)g_stopgo_resume_pid;

    if (sig == 0 && g_recently_disabled_count > 0) {
        int3_iterative_sweep(pid, g_recently_disabled_bps, g_recently_disabled_count);
        g_recently_disabled_count = 0;
    }

    if (sig == 0) {
        resume_app_via_self_id(pid);
        sig = (int)g_stopgo_resume_signal;
    }

    errno = 0;
    long continue_rc = ptrace_raw(PT_CONTINUE, pid, (void *)1, sig);
    int continue_errno = errno;

    if ((int)g_stopgo_resume_signal == 17) {
        if (debug_wait4_bounded(pid, NULL) != 1) continue_rc = -1;
    }

    g_debug_phase = (continue_rc == 0
        || (sig == 0 && continue_rc == -1 && continue_errno == 16))
        ? DEBUG_PHASE_RUNNING
        : DEBUG_PHASE_BROKEN;

    g_stopgo_resume_signal = 0xFFFFFFFFu;
    g_stopgo_resume_pid  = 0;
}

static uint32_t g_last_alive_check = 0;

int dispatch_debug_events(void) {
    #define DDE_RETURN(v) return (v)

    debug_handle_breakpoint_resume();

    struct { uint64_t tv_sec; uint64_t tv_usec; } now = {0,0};

    gettimeofday((struct timeval *)&now, NULL);
    if (((uint32_t)now.tv_sec - g_last_alive_check) > 4) {
        if (!kern_thread_step_walker((int)DBGCTX()->pid)) {
            g_debug_phase = DEBUG_PHASE_BROKEN;
            DDE_RETURN(1);
        }
        g_last_alive_check = (uint32_t)now.tv_sec;
    }

    int debug_pid = (int)DBGCTX()->pid;
    int status = 0;
    int wait_rc;
    if (g_debug_pending_wait_valid
        && g_debug_pending_wait_pid == (uint32_t)debug_pid) {
        status = g_debug_pending_wait_status;
        g_debug_pending_wait_valid = 0;
        g_debug_pending_wait_pid = 0;
        g_debug_pending_wait_status = 0;
        wait_rc = debug_pid;
    } else {
        wait_rc = wait4(debug_pid, &status, 1 , NULL);
    }
    if (wait_rc == 0) DDE_RETURN(0);
    if (wait_rc < 0) {
        g_debug_phase = DEBUG_PHASE_BROKEN;
        DDE_RETURN(1);
    }

    g_debug_phase = DEBUG_PHASE_PROCESSING_EVENT;

    uint8_t sig = (uint8_t)((status >> 8) & 0xFF);
    if (sig == 17) {
        g_debug_phase = DEBUG_PHASE_EVENT_STOPPED;
        DDE_RETURN(0);
    }

    if (sig == 9) {
        int dead_pid = debug_pid;
        debug_full_teardown(curdbgctx);
        ptrace_raw(PT_CONTINUE, dead_pid, (void *)1, 9);
        DDE_RETURN(0);
    }

    uint8_t lwpi[160];
    if (ptrace_raw(PT_LWPINFO, (int)DBGCTX()->pid, lwpi, 160) != 0) {
        resume_app_via_self_id((int)DBGCTX()->pid);
        g_debug_phase = DEBUG_PHASE_BROKEN;
        DDE_RETURN(1);
    }

    if (*(int32_t *)(lwpi + 0x38) == 2 ) {
        int      _abs_lwpid = (int)*(uint32_t *)lwpi;
        uint64_t _abs_rip   = 0;
        if (kern_get_rip_fast((int)DBGCTX()->pid, _abs_lwpid, &_abs_rip) == 0) {
            uint64_t _abs_rm1  = _abs_rip - 1;
            char    *_abs_base = (char *)curdbgctx + 0x10;
            for (int _i = 0; _i < 30; _i++) {
                uint64_t _a = *(uint64_t *)(_abs_base + _i * 0x18);
                if (_a != 0 && _a == _abs_rm1) {
                    long rc = ptrace_raw(PT_CONTINUE, (int)DBGCTX()->pid, (void *)1, 0);
                    g_debug_phase = (rc == 0) ? DEBUG_PHASE_RUNNING : DEBUG_PHASE_BROKEN;
                    DDE_RETURN(0);
                }
            }
        }
    }

    if (*(int32_t *)(lwpi + 0x38) == 1 ) {
        int      _pabs_lwpid = (int)*(uint32_t *)lwpi;
        uint64_t _pabs_rip   = 0;
        if (kern_get_rip_fast((int)DBGCTX()->pid, _pabs_lwpid, &_pabs_rip) == 0) {
            char *_pabs_base = (char *)curdbgctx + 0x10;
            for (int _i = 0; _i < 30; _i++) {
                uint64_t _a = *(uint64_t *)(_pabs_base + _i * 0x18);
                if (_a != 0 && _a == _pabs_rip) {
                    long rc = ptrace_raw(PT_CONTINUE, (int)DBGCTX()->pid, (void *)1, 0);
                    g_debug_phase = (rc == 0) ? DEBUG_PHASE_RUNNING : DEBUG_PHASE_BROKEN;
                    DDE_RETURN(0);
                }
            }
        }
    }

    char pkt[1184];
    memset(pkt, 0, 1184);
    *(uint32_t *)(pkt + 0x000) = *(uint32_t *)lwpi;
    *(uint32_t *)(pkt + 0x004) = (uint32_t)status;
    memcpy(pkt + 0x008, lwpi + 0x80, 24);

    uint8_t regs_buf[176];
    uint8_t fpu_buf[832];
    uint8_t dbreg_buf[128];
    int  pid   = (int)DBGCTX()->pid;
    int  lwpid = (int)*(uint32_t *)lwpi;
    bool got_dbreg = false;

    memset(regs_buf,  0, 176);
    memset(dbreg_buf, 0, 128);

    bool use_kernel = fw_uses_kernel_dbreg_path();
    if (use_kernel) {
        if (kern_get_lwp_full_state(pid, lwpid, regs_buf, dbreg_buf, fpu_buf) == 0) {
            got_dbreg = true;
        } else {
            if (kern_get_proc_info_by_pid(pid, lwpid, regs_buf) != 0
                && ptrace_raw(PT_GETREGS, lwpid, regs_buf, 0) != 0) {
                resume_app_via_self_id(pid);
                g_debug_phase = DEBUG_PHASE_BROKEN;
                DDE_RETURN(1);
            }
            if (kern_proc_install_dbregs(pid, lwpid, fpu_buf) != 0
                && ptrace_raw(PT_GETFPREGS, lwpid, fpu_buf, 0) != 0) {
                resume_app_via_self_id(pid);
                g_debug_phase = DEBUG_PHASE_BROKEN;
                DDE_RETURN(1);
            }
            if (kern_get_dbregs(pid, lwpid, dbreg_buf) == 0) {
                got_dbreg = true;
            }
        }
    } else {
        if (ptrace_raw(PT_GETREGS, lwpid, regs_buf, 0) != 0) {
            resume_app_via_self_id(pid);
            g_debug_phase = DEBUG_PHASE_BROKEN;
            DDE_RETURN(1);
        }
        memset(fpu_buf, 0, 832);
        if (ptrace_raw(PT_GETFPREGS, lwpid, fpu_buf, 0) != 0) {
            resume_app_via_self_id(pid);
            g_debug_phase = DEBUG_PHASE_BROKEN;
            DDE_RETURN(1);
        }
    }

    if (!got_dbreg) {
        if (ptrace_raw(PT_GETDBREGS, lwpid, dbreg_buf, 0) != 0) {
            resume_app_via_self_id(pid);
            g_debug_phase = DEBUG_PHASE_BROKEN;
            DDE_RETURN(1);
        }
    }

    memcpy(pkt + 0x030, regs_buf,  176);
    memcpy(pkt + 0x0E0, fpu_buf,   832);
    memcpy(pkt + 0x420, dbreg_buf, 128);

    uint64_t pkt_rip = *(uint64_t *)(pkt + 0x030 + 0x88);
    uint64_t rip_minus_1 = pkt_rip - 1;
    char *bp_addrs_base = (char *)curdbgctx + 0x10;
    char *matched_bp_v34 = NULL;
    for (int i = 0; i < 30; i++) {
        uint64_t addr = *(uint64_t *)(bp_addrs_base + i * 0x18);
        if (addr != 0 && addr == rip_minus_1) {
            matched_bp_v34 = (char *)curdbgctx + i * 0x18 + 8;
            break;
        }
    }

    int matched_wp = -1;
    uint64_t *pkt_dr = (uint64_t *)(pkt + 0x420);
    /* Internal DBREG writes clear live DR6; retain this event's cause for the client. */
    uint64_t event_dr6 = pkt_dr[6];
    bool report_event_dr6 = true;
    for (int i = 0; i < 4; i++) {
        if (pkt_dr[i] != 0 && pkt_dr[i] == pkt_rip) { matched_wp = i; break; }
    }

    if (matched_bp_v34 != NULL &&
        *(int32_t *)(lwpi + 0x38) == 2 ) {

        long rc = ptrace_raw(PT_CONTINUE, (int)DBGCTX()->pid, (void *)1, 0);
        g_debug_phase = (rc == 0) ? DEBUG_PHASE_RUNNING : DEBUG_PHASE_BROKEN;
        DDE_RETURN(0);
    }

    if (*(int32_t *)(lwpi + 0x38) == 2) {
        pkt_dr[6] = 0;
    }

    uint8_t length_buf[176];

    if (matched_wp >= 0) {
        int      cl1 = matched_wp * 2;
        int      cl2 = matched_wp * 4 + 16;
        uint64_t saved_dr7 = pkt_dr[7];
        uint64_t rw_bits   = (saved_dr7 >> cl2) & 3;
        uint64_t clear_mask = ~(((uint64_t)0xF << cl2) | ((uint64_t)3 << cl1));

        int numlwps = (int)ptrace_raw(PT_GETNUMLWPS, pid, NULL, 0);
        if (numlwps > 0) {
            uint32_t *lwpids = (uint32_t *)net_alloc_buffer((uint64_t)numlwps * 4);
            if (lwpids) {
                if (ptrace_raw(PT_GETLWPLIST, pid, lwpids, numlwps) > 0) {
                    for (int i = 0; i < numlwps; i++) {
                        int lwp = (int)lwpids[i];
                        if (lwp == lwpid) {
                            if (rw_bits == 0) {
                                uint64_t saved_pkt_dr7 = pkt_dr[7];
                                pkt_dr[7] &= clear_mask;
                                if (use_kernel) {
                                    if (kern_set_dbregs(pid, lwpid, pkt + 0x420) != 0) {
                                        ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
                                    }
                                } else {
                                    ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
                                }
                                ptrace_raw(PT_STEP, lwpid, (void *)1, 0);
                                int s2 = 0;
                                while (wait4(pid, &s2, 1, NULL) == 0) {
                                    sceKernelUsleep(50);
                                }
                                pkt_dr[7] = saved_pkt_dr7;
                                if (use_kernel) {
                                    kern_set_dbregs(pid, lwpid, pkt + 0x420);
                                } else {
                                    ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
                                }
                            }
                            continue;
                        }
                        if (use_kernel) {
                            if (kern_get_proc_info_by_pid(pid, lwp, length_buf) != 0) {
                                ptrace_raw(PT_GETREGS, lwp, length_buf, 0);
                            }
                        } else {
                            ptrace_raw(PT_GETREGS, lwp, length_buf, 0);
                        }
                        uint64_t thr_rip = *(uint64_t *)(length_buf + 0x88);
                        if (thr_rip != pkt_rip) continue;
                        uint8_t small_dbreg[128];
                        ptrace_raw(PT_GETDBREGS, lwp, small_dbreg, 0);
                        uint64_t thr_dr7 = *(uint64_t *)(small_dbreg + 0x38);
                        if (((thr_dr7 >> cl2) & 3) != 0) continue;
                        uint64_t saved_thr_dr7 = thr_dr7;
                        *(uint64_t *)(small_dbreg + 0x38) = thr_dr7 & clear_mask;
                        ptrace_raw(PT_SETDBREGS, lwp, small_dbreg, 0);
                        ptrace_raw(PT_STEP, lwp, (void *)1, 0);
                        int s3 = 0;
                        while (wait4(pid, &s3, 1, NULL) == 0) {
                            sceKernelUsleep(50);
                        }
                        *(uint64_t *)(small_dbreg + 0x38) = saved_thr_dr7;
                        if (use_kernel) {
                            kern_set_dbregs(pid, lwp, small_dbreg);
                        } else {
                            ptrace_raw(PT_SETDBREGS, lwp, small_dbreg, 0);
                        }
                    }
                }
                free(lwpids);
            }
        } else if (rw_bits == 0) {
            uint64_t saved_pkt_dr7 = pkt_dr[7];
            pkt_dr[7] = saved_pkt_dr7 & clear_mask;
            if (use_kernel) {
                if (kern_set_dbregs(pid, lwpid, pkt + 0x420) != 0) {
                    ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
                }
            } else {
                ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
            }
            ptrace_raw(PT_STEP, lwpid, (void *)1, 0);
            int s4 = 0;
            while (wait4(pid, &s4, 1, NULL) == 0) sceKernelUsleep(50);
            pkt_dr[7] = saved_pkt_dr7;
            if (use_kernel) {
                kern_set_dbregs(pid, lwpid, pkt + 0x420);
            } else {
                ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
            }
        }
    }

    if (matched_bp_v34 == NULL && matched_wp < 0 && *(int32_t *)(lwpi + 0x38) == 2) {
        uint64_t _dr7 = pkt_dr[7];
        int _is_data_wp = 0;
        for (int _i = 0; _i < 4; _i++) {
            int _en = (int)((_dr7 >> (_i * 2)) & 3);
            int _rw = (int)((_dr7 >> (16 + _i * 4)) & 3);
            if (_en && _rw != 0 && pkt_dr[_i] != 0) { _is_data_wp = 1; break; }
        }
        if (_is_data_wp) {
            uint64_t _saved_dr6 = pkt_dr[6];
            pkt_dr[6] = 0;
            if (use_kernel) {
                if (kern_set_dbregs(pid, lwpid, pkt + 0x420) != 0)
                    ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
            } else {
                ptrace_raw(PT_SETDBREGS, lwpid, pkt + 0x420, 0);
            }
            pkt_dr[6] = _saved_dr6;
        }
    }

    if (matched_bp_v34 != NULL) {
        uint64_t bp_addr        = *(uint64_t *)(matched_bp_v34 + 8);
        char    *saved_byte_ptr =  matched_bp_v34 + 16;
        uint8_t  int3           = 0xCC;

        uint64_t saved_authid_1 = 0;
        int authid_bumped_1 = (authid_bump_safe(&saved_authid_1) == 0);

        proc_write_mem((uint32_t)pid, bp_addr, 1, saved_byte_ptr);
        *(uint64_t *)(pkt + 0x030 + 0x88) -= 1;

        if (use_kernel) {
            uint64_t _new_rip = *(uint64_t *)(pkt + 0x030 + 0x88);
            if (kern_set_rip_fast(pid, lwpid, _new_rip) != 0) {
                if (kern_apply_thread_dbgctx(pid, lwpid, pkt + 0x030) != 0) {
                    ptrace_raw(PT_SETREGS, lwpid, pkt + 0x030, 0);
                }
            }
        } else {
            ptrace_raw(PT_SETREGS, lwpid, pkt + 0x030, 0);
        }
        ptrace_raw(PT_STEP, lwpid, (void *)1, 0);

        if (authid_bumped_1) {
            authid_restore_safe(saved_authid_1);
            authid_bumped_1 = 0;
        }

        int s_step = 0;
        while (wait4(pid, &s_step, 1, NULL) == 0) sceKernelUsleep(50);

        uint64_t saved_authid_2 = 0;
        int authid_bumped_2 = (authid_bump_safe(&saved_authid_2) == 0);

        int need_scan = 0;
        int cons_lw   = -1;
        {
            uint8_t lwpi_peek[160];
            if (ptrace_raw(PT_LWPINFO, pid, lwpi_peek, 160) == 0) {
                cons_lw = (int)*(uint32_t *)lwpi_peek;
                if (cons_lw != 0 && cons_lw != lwpid) need_scan = 1;
            } else {
                need_scan = 1;
            }
        }

        if (need_scan) {
            uint64_t target_rip = bp_addr + 1;
            int rewound = 0;

            if (cons_lw > 0 && cons_lw != lwpid) {
                uint64_t cons_rip = 0;
                if (kern_get_rip_fast(pid, cons_lw, &cons_rip) == 0
                    && cons_rip == target_rip) {
                    uint8_t cons_li[160];
                    if (ptrace_raw(PT_LWPINFO, cons_lw, cons_li, 160) == 0
                        && *(int32_t *)(cons_li + 0x04) == 1
                        && *(int32_t *)(cons_li + 0x30) == 5
                        && *(int32_t *)(cons_li + 0x38) == 1 ) {
                        uint8_t cons_regs[176];
                        if (kern_get_proc_info_by_pid(pid, cons_lw, cons_regs) == 0
                            && *(uint64_t *)(cons_regs + 0x88) == target_rip) {
                            *(uint64_t *)(cons_regs + 0x88) = bp_addr;
                            kern_apply_thread_dbgctx(pid, cons_lw, cons_regs);
                            rewound = 1;
                        }
                    }
                }
            }

            if (!rewound) {
                uint32_t *sib_lwpids = NULL;
                int sib_count = 0;
                if (get_lwp_list_cached(pid, &sib_lwpids, &sib_count) == 0) {
                    for (int i = 0; i < sib_count; i++) {
                        int sib_lw = (int)sib_lwpids[i];
                        if (sib_lw == lwpid) continue;
                        if (sib_lw == cons_lw) continue;
                        uint64_t sib_rip = 0;
                        if (kern_get_rip_fast(pid, sib_lw, &sib_rip) != 0) continue;
                        if (sib_rip != target_rip) continue;

                        uint8_t sib_li[160];
                        if (ptrace_raw(PT_LWPINFO, sib_lw, sib_li, 160) != 0)
                            continue;
                        if (*(int32_t *)(sib_li + 0x04) != 1 ) continue;
                        if (*(int32_t *)(sib_li + 0x30) != 5 )        continue;
                        if (*(int32_t *)(sib_li + 0x38) != 1 )     continue;

                        uint8_t sib_regs[176];
                        if (kern_get_proc_info_by_pid(pid, sib_lw, sib_regs) != 0) continue;
                        if (*(uint64_t *)(sib_regs + 0x88) == target_rip) {
                            *(uint64_t *)(sib_regs + 0x88) = bp_addr;
                            kern_apply_thread_dbgctx(pid, sib_lw, sib_regs);
                        }
                    }
                }
            }
        }
        proc_write_mem((uint32_t)pid, bp_addr, 1, &int3);

        if (authid_bumped_2) authid_restore_safe(saved_authid_2);
    }

    uint32_t pkt_lwpid = *(uint32_t *)pkt;
    int stepping = (int)g_stepping_lwpid;
    if (stepping > 0) {
        if ((int)pkt_lwpid != stepping) {
            long rc = ptrace_raw(PT_CONTINUE, (int)pkt_lwpid, (void *)1, 0);
            g_debug_phase = (rc == 0) ? DEBUG_PHASE_STEPPING : DEBUG_PHASE_BROKEN;
            DDE_RETURN(0);
        }
        *(uint64_t *)(pkt + 0x420 + 0x30) = 0;
        report_event_dr6 = false;
    }
    g_stepping_lwpid = 0;

    {
        uint32_t  _final_lwpid = *(uint32_t *)pkt;
        uint64_t  _final_rip   = *(uint64_t *)(pkt + 0x030 + 0x88);
        uint8_t   _final_sig   = sig;
        int       _is_fatal    = DBG_STORM_FATAL_SIGS(_final_sig);
        int       _match_last  = (_final_lwpid == g_storm_lwpid) &&
                                 (_final_rip   == g_storm_rip)   &&
                                 (_final_sig   == g_storm_sig);
        if (_is_fatal && _match_last) {
            if (++g_storm_count > DBG_STORM_LIMIT) {

                g_debug_phase = DEBUG_PHASE_EVENT_STOPPED;
                DDE_RETURN(0);
            }
        } else {
            g_storm_count = 0;
        }
        g_storm_lwpid = _final_lwpid;
        g_storm_rip   = _final_rip;
        g_storm_sig   = _final_sig;
    }

    g_debug_phase = DEBUG_PHASE_EVENT_STOPPED;
    if (report_event_dr6) pkt_dr[6] = event_dr6;
    if (net_send_all(DBGCTX()->dbgfd, pkt, 1184) < 0) {
        g_debug_phase = DEBUG_PHASE_BROKEN;
        DDE_RETURN(1);
    }
    resume_app_via_self_id((int)DBGCTX()->pid);
    DDE_RETURN(0);

    #undef DDE_RETURN
}

int debug_handle(int fd, struct cmd_packet *packet) {
    switch (packet->cmd) {
    case 0xBDBB0500u: return debug_process_stop_handle(fd, packet);
    case 0xBDBB0001u: return debug_attach_handle(fd, packet);
    case 0xBDBB0002u: return debug_detach_handle(fd, packet);
    case 0xBDBB0003u: return debug_set_breakpoint_handle(fd, packet);
    case 0xBDBB0004u: return debug_set_watchpoint_handle(fd, packet);
    case 0xBDBB0005u: return debug_get_thread_list_handle(fd, packet);
    case 0xBDBB0006u: return debug_suspend_thread_handle(fd, packet);
    case 0xBDBB0007u: return debug_resume_thread_handle(fd, packet);
    case 0xBDBB0008u: return debug_getregs_handle(fd, packet);
    case 0xBDBB0009u: return debug_setregs_handle(fd, packet);
    case 0xBDBB000Au: return debug_getfpregs_handle(fd, packet);
    case 0xBDBB000Bu: return debug_setfpregs_handle(fd, packet);
    case 0xBDBB000Cu: return debug_getdbregs_handle(fd, packet);
    case 0xBDBB000Du: return debug_setdbregs_handle(fd, packet);
    case 0xBDBB000Eu: return debug_getfsgsbase_handle(fd, packet);
    case 0xBDBB000Fu: return debug_setfsgsbase_handle(fd, packet);
    case 0xBDBB0010u: return debug_continue_handle(fd, packet);
    case 0xBDBB0011u: return debug_thread_info_handle(fd, packet);
    case 0xBDBB0012u: return debug_step_handle(fd, packet);
    case 0xBDBB0013u: return debug_step_thread_handle(fd, packet);
    }
    net_send_int32(fd, CMD_ERROR);
    return 0;
}
