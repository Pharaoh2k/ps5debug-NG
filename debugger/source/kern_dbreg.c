// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "kern_rw_fast.h"
#include <stdint.h>
#include <stdbool.h>

static uint32_t g_fw_cache = 0;

bool fw_uses_kernel_dbreg_path(void) {
    uint32_t fw = g_fw_cache;
    if (fw == 0) {
        fw = kernel_get_fw_version();
        g_fw_cache = fw;
    }
    switch (fw & 0xffff0000u) {
    case 0x3000000u: case 0x3100000u: case 0x3200000u: case 0x3210000u:                 /* 3.00 3.10 3.20 3.21 */
    case 0x4000000u: case 0x4020000u: case 0x4030000u: case 0x4500000u: case 0x4510000u: /* 4.00 4.02 4.03 4.50 4.51 */
    case 0x5000000u: case 0x5020000u: case 0x5100000u: case 0x5500000u:                  /* 5.00 5.02 5.10 5.50 */
    case 0x6000000u: case 0x6020000u: case 0x6500000u:                                   /* 6.00 6.02 6.50 */
    case 0x7200000u: case 0x7400000u: case 0x7600000u: case 0x7610000u:                  /* 7.20 7.40 7.60 7.61 (not 7.00/7.01) */
    case 0x8000000u: case 0x8200000u: case 0x8400000u: case 0x8600000u:                  /* 8.00 8.20 8.40 8.60 */
    case 0x9000000u: case 0x9050000u: case 0x9200000u: case 0x9400000u: case 0x9600000u: /* 9.00 9.05 9.20 9.40 9.60 */
    case 0x10000000u: case 0x10010000u: case 0x10200000u: case 0x10400000u: case 0x10600000u: /* 10.00 10.01 10.20 10.40 10.60 */
    case 0x11000000u: case 0x11200000u: case 0x11400000u: case 0x11600000u:                    /* 11.00 11.20 11.40 11.60 */
    case 0x12000000u: case 0x12020000u: case 0x12200000u: case 0x12400000u: case 0x12600000u: case 0x12700000u: /* 12.00 12.02 12.20 12.40 12.60 12.70 */
    case 0x13000000u: case 0x13200000u: case 0x13400000u: case 0x13420000u: case 0x13600000u:  /* 13.00 13.20 13.40 13.42 13.60 */
        return true;
    default:
        return false;
    }
}

bool is_process_stopped(int pid) {
    int status;
    if (wait4(pid, &status, 7, NULL) <= 0) return false;
    return ((unsigned char *)&status)[1] == 0x11;
}

bool kern_thread_step_walker(int pid) {
    intptr_t cur_proc  = 0;
    intptr_t next_proc = 0;
    int32_t  cur_pid   = 0;

    if (kernel_copyout_fast(KERNEL_ADDRESS_ALLPROC, &cur_proc, 8) != 0) return false;
    if (!cur_proc) return false;

    for (;;) {
        if (kernel_copyout_fast(cur_proc + KERNEL_OFFSET_PROC_P_PID, &cur_pid, 4) != 0)
            return false;
        if (cur_pid == pid) return true;
        if (kernel_copyout_fast(cur_proc, &next_proc, 8) != 0) return false;
        cur_proc = next_proc;
        if (!cur_proc) return false;
    }
}

#define KR_THR_CACHE_N 8
static struct { int32_t pid; int32_t lwpid; uint64_t kthread; } kr_thr_cache[KR_THR_CACHE_N];
static int kr_thr_cache_next = 0;

void kern_thread_cache_flush(void) {
    for (int i = 0; i < KR_THR_CACHE_N; i++) {
        kr_thr_cache[i].pid = 0; kr_thr_cache[i].lwpid = 0; kr_thr_cache[i].kthread = 0;
    }
}

intptr_t kern_thread_addr(int pid, int lwpid) {
    for (int i = 0; i < KR_THR_CACHE_N; i++) {
        if (kr_thr_cache[i].pid == (int32_t)pid && kr_thr_cache[i].lwpid == (int32_t)lwpid
            && kr_thr_cache[i].kthread != 0) {
            uint32_t v = 0;
            if (kernel_copyout_fast((intptr_t)(kr_thr_cache[i].kthread + 0x9c), &v, 4) == 0
                && (int32_t)v == (int32_t)lwpid)
                return (intptr_t)kr_thr_cache[i].kthread;
            kr_thr_cache[i].pid = 0; kr_thr_cache[i].lwpid = 0; kr_thr_cache[i].kthread = 0;
            break;
        }
    }

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return 0;

    uint8_t chain_hdr[0x30];
    if (kernel_copyout_fast(kproc + 0x10, chain_hdr, 0x30) < 0) return 0;
    intptr_t kthread = *(intptr_t *)chain_hdr;

    uint8_t tbuf[0x680];
    while (kthread) {
        if (kernel_copyout_fast(kthread, tbuf, 0x680) < 0) return 0;
        if (*(uint32_t *)(tbuf + 0x9c) == (uint32_t)lwpid) {
            kr_thr_cache[kr_thr_cache_next].pid     = (int32_t)pid;
            kr_thr_cache[kr_thr_cache_next].lwpid   = (int32_t)lwpid;
            kr_thr_cache[kr_thr_cache_next].kthread = (uint64_t)kthread;
            kr_thr_cache_next = (kr_thr_cache_next + 1) % KR_THR_CACHE_N;
            return kthread;
        }
        kthread = *(intptr_t *)(tbuf + 0x10);
    }
    return 0;
}

int kern_get_dbregs(int pid, int lwpid, void *dbreg_buf) {
    if (pid == 0)        return 1;
    if (!dbreg_buf)      return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    uint8_t pcb_buf[0x178];
    if (kernel_copyout_fast(pcb_addr, pcb_buf, 0x178) < 0) return 1;

    uint8_t *dst = (uint8_t *)dbreg_buf;
    *(uint64_t *)(dst + 0x00) = *(uint64_t *)(pcb_buf + 0x78);
    *(uint64_t *)(dst + 0x08) = *(uint64_t *)(pcb_buf + 0x80);
    *(uint64_t *)(dst + 0x10) = *(uint64_t *)(pcb_buf + 0x88);
    *(uint64_t *)(dst + 0x18) = *(uint64_t *)(pcb_buf + 0x90);
    *(uint64_t *)(dst + 0x30) = *(uint64_t *)(pcb_buf + 0x98);
    *(uint64_t *)(dst + 0x38) = *(uint64_t *)(pcb_buf + 0xa0);
    return 0;
}

int kern_set_dbregs(int pid, int lwpid, void *dbreg_buf) {
    if (pid == 0)        return 1;
    if (!dbreg_buf)      return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    uint8_t pcb_buf[0x178];
    if (kernel_copyout_fast(pcb_addr, pcb_buf, 0x178) < 0) return 1;

    const uint8_t *src = (const uint8_t *)dbreg_buf;
    *(uint64_t *)(pcb_buf + 0x78) = *(uint64_t *)(src + 0x00);
    *(uint64_t *)(pcb_buf + 0x80) = *(uint64_t *)(src + 0x08);
    *(uint64_t *)(pcb_buf + 0x88) = *(uint64_t *)(src + 0x10);
    *(uint64_t *)(pcb_buf + 0x90) = *(uint64_t *)(src + 0x18);
    *(uint64_t *)(pcb_buf + 0x98) = *(uint64_t *)(src + 0x30);
    *(uint64_t *)(pcb_buf + 0xa0) = *(uint64_t *)(src + 0x38);

    int rc = kernel_copyin_fast(pcb_buf, pcb_addr, 0x178);
    return (rc < 0) ? 1 : 0;
}

int kern_proc_install_dbregs(int pid, int lwpid, void *fpu_buf) {
    if (pid == 0)        return 1;
    if (!fpu_buf)        return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    uint8_t pcb_buf[0x178];
    if (kernel_copyout_fast(pcb_addr, pcb_buf, 0x178) < 0) return 1;

    intptr_t kfpu_addr = *(intptr_t *)(pcb_buf + 0x148);
    int rc = kernel_copyout_fast(kfpu_addr, fpu_buf, 0x340);
    return (rc < 0) ? 1 : 0;
}

int kern_get_fpregs(int pid, int lwpid, void *fpu_buf) {
    if (pid == 0)        return 1;
    if (!fpu_buf)        return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    intptr_t kfpu_addr;
    if (kernel_copyout_fast(pcb_addr + 0x148, &kfpu_addr, 8) < 0) return 1;
    if (!kfpu_addr)      return 1;

    if (kernel_copyout_fast(kfpu_addr, fpu_buf, 0x340) < 0) return 1;
    return 0;
}

int kern_set_fpregs(int pid, int lwpid, const void *fpu_buf) {
    if (pid == 0)        return 1;
    if (!fpu_buf)        return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    intptr_t kfpu_addr;
    if (kernel_copyout_fast(pcb_addr + 0x148, &kfpu_addr, 8) < 0) return 1;
    if (!kfpu_addr)      return 1;

    if (kernel_copyin_fast(fpu_buf, kfpu_addr, 0x340) < 0) return 1;
    return 0;
}

int kern_get_fsgsbase(int pid, int lwpid, void *out16) {
    if (pid == 0)        return 1;
    if (!out16)          return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    if (kernel_copyout_fast(pcb_addr + 0x40, out16, 16) < 0) return 1;
    return 0;
}

int kern_set_fsgsbase(int pid, int lwpid, const void *in16) {
    if (pid == 0)        return 1;
    if (!in16)           return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 6;

    intptr_t pcb_addr;
    if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

    if (kernel_copyin_fast(in16, pcb_addr + 0x40, 16) < 0) return 1;
    return 0;
}

int kern_get_proc_info_by_pid(int pid, int lwpid, void *regs_buf) {
    if (pid == 0)        return 1;
    if (!regs_buf)       return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 1;

    intptr_t frame_addr;
    if (kernel_copyout_fast(kthread + 0x460, &frame_addr, 8) < 0) return 1;

    uint8_t fbuf[0x110];
    memset(fbuf, 0, 0x110);
    if (kernel_copyout_fast(frame_addr, fbuf, 0x110) < 0) return 1;

    uint8_t *dst = (uint8_t *)regs_buf;
    *(uint64_t *)(dst + 0x00) = *(uint64_t *)(fbuf + 0x70);
    *(uint64_t *)(dst + 0x08) = *(uint64_t *)(fbuf + 0x68);
    *(uint64_t *)(dst + 0x10) = *(uint64_t *)(fbuf + 0x60);
    *(uint64_t *)(dst + 0x18) = *(uint64_t *)(fbuf + 0x58);
    *(uint64_t *)(dst + 0x20) = *(uint64_t *)(fbuf + 0x50);
    *(uint64_t *)(dst + 0x28) = *(uint64_t *)(fbuf + 0x48);
    *(uint64_t *)(dst + 0x30) = *(uint64_t *)(fbuf + 0x28);
    *(uint64_t *)(dst + 0x38) = *(uint64_t *)(fbuf + 0x20);
    *(uint64_t *)(dst + 0x40) = *(uint64_t *)(fbuf + 0x00);
    *(uint64_t *)(dst + 0x48) = *(uint64_t *)(fbuf + 0x08);
    *(uint64_t *)(dst + 0x50) = *(uint64_t *)(fbuf + 0x40);
    *(uint64_t *)(dst + 0x58) = *(uint64_t *)(fbuf + 0x38);
    *(uint64_t *)(dst + 0x60) = *(uint64_t *)(fbuf + 0x10);
    *(uint64_t *)(dst + 0x68) = *(uint64_t *)(fbuf + 0x18);
    *(uint64_t *)(dst + 0x70) = *(uint64_t *)(fbuf + 0x30);
    *(uint64_t *)(dst + 0x78) = *(uint64_t *)(fbuf + 0x78);
    *(uint64_t *)(dst + 0x88) = *(uint64_t *)(fbuf + 0xe8);
    *(uint64_t *)(dst + 0x90) = *(uint64_t *)(fbuf + 0xf0);
    *(uint64_t *)(dst + 0x98) = *(uint64_t *)(fbuf + 0xf8);
    *(uint64_t *)(dst + 0xa0) = *(uint64_t *)(fbuf + 0x100);
    *(uint64_t *)(dst + 0xa8) = *(uint64_t *)(fbuf + 0x108);
    *(uint32_t *)(dst + 0x84) = *(uint32_t *)(fbuf + 0x8c);
    *(uint32_t *)(dst + 0x80) = (uint32_t)(*(uint64_t *)(fbuf + 0xe0));
    return 0;
}

int kern_apply_thread_dbgctx(int pid, int lwpid, void *regs_buf) {
    if (pid == 0)        return 1;
    if (!regs_buf)       return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 1;

    intptr_t frame_addr;
    if (kernel_copyout_fast(kthread + 0x460, &frame_addr, 8) < 0) return 1;

    uint8_t fbuf[0x110];
    memset(fbuf, 0, 0x110);
    if (kernel_copyout_fast(frame_addr, fbuf, 0x110) < 0) return 1;

    const uint8_t *src = (const uint8_t *)regs_buf;
    *(uint64_t *)(fbuf + 0x70) = *(uint64_t *)(src + 0x00);
    *(uint64_t *)(fbuf + 0x68) = *(uint64_t *)(src + 0x08);
    *(uint64_t *)(fbuf + 0x60) = *(uint64_t *)(src + 0x10);
    *(uint64_t *)(fbuf + 0x58) = *(uint64_t *)(src + 0x18);
    *(uint64_t *)(fbuf + 0x50) = *(uint64_t *)(src + 0x20);
    *(uint64_t *)(fbuf + 0x48) = *(uint64_t *)(src + 0x28);
    *(uint64_t *)(fbuf + 0x28) = *(uint64_t *)(src + 0x30);
    *(uint64_t *)(fbuf + 0x20) = *(uint64_t *)(src + 0x38);
    *(uint64_t *)(fbuf + 0x00) = *(uint64_t *)(src + 0x40);
    *(uint64_t *)(fbuf + 0x08) = *(uint64_t *)(src + 0x48);
    *(uint64_t *)(fbuf + 0x40) = *(uint64_t *)(src + 0x50);
    *(uint64_t *)(fbuf + 0x38) = *(uint64_t *)(src + 0x58);
    *(uint64_t *)(fbuf + 0x10) = *(uint64_t *)(src + 0x60);
    *(uint64_t *)(fbuf + 0x18) = *(uint64_t *)(src + 0x68);
    *(uint64_t *)(fbuf + 0x30) = *(uint64_t *)(src + 0x70);
    *(uint64_t *)(fbuf + 0x78) = *(uint64_t *)(src + 0x78);
    *(uint64_t *)(fbuf + 0xe8) = *(uint64_t *)(src + 0x88);
    *(uint64_t *)(fbuf + 0xf0) = *(uint64_t *)(src + 0x90);
    *(uint64_t *)(fbuf + 0xf8) = *(uint64_t *)(src + 0x98);
    *(uint64_t *)(fbuf + 0x100) = *(uint64_t *)(src + 0xa0);
    *(uint64_t *)(fbuf + 0x108) = *(uint64_t *)(src + 0xa8);
    *(uint32_t *)(fbuf + 0x8c) = *(uint32_t *)(src + 0x84);
    *(uint64_t *)(fbuf + 0xe0) = (uint64_t)(*(uint32_t *)(src + 0x80));

    int rc = kernel_copyin_fast(fbuf, frame_addr, 0x110);
    return (rc < 0) ? 1 : 0;
}

int kern_get_lwp_full_state(int pid, int lwpid, void *regs_buf,
                             void *dbreg_buf, void *fpu_buf) {
    if (pid == 0)        return 1;
    if (!regs_buf)       return 1;

    intptr_t kthread = kern_thread_addr(pid, lwpid);
    if (!kthread)        return 1;

    intptr_t frame_addr;
    if (kernel_copyout_fast(kthread + 0x460, &frame_addr, 8) < 0) return 1;

    uint8_t fbuf[0x110];
    memset(fbuf, 0, 0x110);
    if (kernel_copyout_fast(frame_addr, fbuf, 0x110) < 0) return 1;

    uint8_t *dst = (uint8_t *)regs_buf;
    *(uint64_t *)(dst + 0x00) = *(uint64_t *)(fbuf + 0x70);
    *(uint64_t *)(dst + 0x08) = *(uint64_t *)(fbuf + 0x68);
    *(uint64_t *)(dst + 0x10) = *(uint64_t *)(fbuf + 0x60);
    *(uint64_t *)(dst + 0x18) = *(uint64_t *)(fbuf + 0x58);
    *(uint64_t *)(dst + 0x20) = *(uint64_t *)(fbuf + 0x50);
    *(uint64_t *)(dst + 0x28) = *(uint64_t *)(fbuf + 0x48);
    *(uint64_t *)(dst + 0x30) = *(uint64_t *)(fbuf + 0x28);
    *(uint64_t *)(dst + 0x38) = *(uint64_t *)(fbuf + 0x20);
    *(uint64_t *)(dst + 0x40) = *(uint64_t *)(fbuf + 0x00);
    *(uint64_t *)(dst + 0x48) = *(uint64_t *)(fbuf + 0x08);
    *(uint64_t *)(dst + 0x50) = *(uint64_t *)(fbuf + 0x40);
    *(uint64_t *)(dst + 0x58) = *(uint64_t *)(fbuf + 0x38);
    *(uint64_t *)(dst + 0x60) = *(uint64_t *)(fbuf + 0x10);
    *(uint64_t *)(dst + 0x68) = *(uint64_t *)(fbuf + 0x18);
    *(uint64_t *)(dst + 0x70) = *(uint64_t *)(fbuf + 0x30);
    *(uint64_t *)(dst + 0x78) = *(uint64_t *)(fbuf + 0x78);
    *(uint64_t *)(dst + 0x88) = *(uint64_t *)(fbuf + 0xe8);
    *(uint64_t *)(dst + 0x90) = *(uint64_t *)(fbuf + 0xf0);
    *(uint64_t *)(dst + 0x98) = *(uint64_t *)(fbuf + 0xf8);
    *(uint64_t *)(dst + 0xa0) = *(uint64_t *)(fbuf + 0x100);
    *(uint64_t *)(dst + 0xa8) = *(uint64_t *)(fbuf + 0x108);
    *(uint32_t *)(dst + 0x84) = *(uint32_t *)(fbuf + 0x8c);
    *(uint32_t *)(dst + 0x80) = (uint32_t)(*(uint64_t *)(fbuf + 0xe0));

    if (dbreg_buf || fpu_buf) {
        intptr_t pcb_addr;
        if (kernel_copyout_fast(kthread + 0x3f8, &pcb_addr, 8) < 0) return 1;

        uint8_t pcb_buf[0x178];
        if (kernel_copyout_fast(pcb_addr, pcb_buf, 0x178) < 0) return 1;

        if (dbreg_buf) {
            uint8_t *db = (uint8_t *)dbreg_buf;
            *(uint64_t *)(db + 0x00) = *(uint64_t *)(pcb_buf + 0x78);
            *(uint64_t *)(db + 0x08) = *(uint64_t *)(pcb_buf + 0x80);
            *(uint64_t *)(db + 0x10) = *(uint64_t *)(pcb_buf + 0x88);
            *(uint64_t *)(db + 0x18) = *(uint64_t *)(pcb_buf + 0x90);
            *(uint64_t *)(db + 0x30) = *(uint64_t *)(pcb_buf + 0x98);
            *(uint64_t *)(db + 0x38) = *(uint64_t *)(pcb_buf + 0xa0);
        }

        if (fpu_buf) {
            intptr_t kfpu_addr = *(intptr_t *)(pcb_buf + 0x148);
            if (kfpu_addr) {
                if (kernel_copyout_fast(kfpu_addr, fpu_buf, 0x340) < 0) return 1;
            }
        }
    }

    return 0;
}
