// SPDX-License-Identifier: GPL-3.0-only

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "sdk_shim.h"
#include "proc.h"
#include "kern_rw_fast.h"
#include "write_policy.h"

extern void    *g_proc_rw_mutex;

static int priv_syscall_573(uint64_t *cmd, uint64_t *args, uint64_t *out)
{
    int self_pid = getpid();

    intptr_t ucred = kernel_get_proc_ucred_fast((pid_t)self_pid);
    if (ucred == 0) return -1;

    unsigned long saved_authid = 0;
    if (kernel_copyout_fast(ucred + 0x58, &saved_authid, sizeof(saved_authid)) != 0) return -1;
    if (saved_authid == 0) return -1;

    uint64_t priv_authid = 0x4800000000000006ULL;
    if (kernel_copyin_fast(&priv_authid, ucred + 0x58, sizeof(priv_authid)) != 0) return -1;

    unsigned int syscall_rc = (unsigned int)__crt_syscall(573, cmd, args, out);

    int restore_rc = kernel_copyin_fast(&saved_authid, ucred + 0x58, sizeof(saved_authid));

    return (restore_rc != 0 ? -1 : 0) | (int)syscall_rc;
}

static int sys_proc_rw_inner(uint32_t pid, uint64_t address, void *data,
                              uint64_t length, uint64_t *arg5_out, int write)
{
    uint64_t cmd_struct[2]  = { 1, write ? 0x13ull : 0x12ull };
    uint64_t args_struct[4] = { (uint64_t)(int64_t)(int32_t)pid,
                                address, (uint64_t)data, length };
    uint64_t out_struct[2]  = { 0, 0 };

    if (length == 0) {
        if (arg5_out) *arg5_out = 0;
        return 0;
    }

    int syscall_rc = priv_syscall_573(cmd_struct, args_struct, out_struct);

    if (syscall_rc != 0 || out_struct[1] != length) return 1;

    if (arg5_out) *arg5_out = length;
    return 0;
}

static long sys_proc_rw(uint64_t pid, uint64_t address, uint64_t length,
                         void *data, uint64_t arg5, int write)
{
    scePthreadMutexLock(&g_proc_rw_mutex);
    int rc;
    if (write && length != 0 && ps5debug_write_needs_prefix(address)) {
        int diagnostic = ps5debug_write_diagnostics_enabled();
        rc = 1;
        if (data && length != SIZE_MAX) {
            uint8_t *prefixed = (uint8_t *)malloc((size_t)length + 1);
            if (prefixed) {
                uint64_t read = 0;
                rc = sys_proc_rw_inner((uint32_t)pid, address - 1,
                                       prefixed, 1, &read, 0);
                if (rc == 0 && read == 1) {
                    memcpy(prefixed + 1, data, (size_t)length);
                    uint8_t leading = prefixed[0];
                    uint64_t wrote = 0;
                    if (diagnostic) {
                        klog_printf("[write:mdbg] pid=%u va=0x%llx len=%llu "
                                    "step=prefix-normalize shifted=0x%llx "
                                    "shifted-len=%llu\n",
                                    (uint32_t)pid,
                                    (unsigned long long)address,
                                    (unsigned long long)length,
                                    (unsigned long long)(address - 1),
                                    (unsigned long long)(length + 1));
                    }
                    int write_rc =
                        sys_proc_rw_inner((uint32_t)pid, address - 1,
                                          prefixed, length + 1,
                                          &wrote, 1);

                    const uint8_t *expected = (const uint8_t *)data;
                    prefixed[0] = leading ^ 0xFFu;
                    for (uint64_t i = 0; i < length; i++)
                        prefixed[i + 1] = expected[i] ^ 0xFFu;
                    uint64_t verified = 0;
                    int verify_rc =
                        sys_proc_rw_inner((uint32_t)pid, address - 1,
                                          prefixed, length + 1,
                                          &verified, 0);
                    int exact = write_rc == 0 && wrote == length + 1
                        && verify_rc == 0
                        && verified == length + 1
                        && prefixed[0] == leading
                        && memcmp(prefixed + 1, expected,
                                  (size_t)length) == 0;
                    if (diagnostic || !exact) {
                        klog_printf("[write:mdbg] pid=%u va=0x%llx len=%llu "
                                    "write-rc=%d wrote=%llu verify-rc=%d "
                                    "verified=%llu exact=%d\n",
                                    (uint32_t)pid,
                                    (unsigned long long)address,
                                    (unsigned long long)length,
                                    write_rc, (unsigned long long)wrote,
                                    verify_rc,
                                    (unsigned long long)verified, exact);
                    }
                    rc = exact ? 0 : 1;
                    if (exact && arg5)
                        *(uint64_t *)(uintptr_t)arg5 = length;
                }
                free(prefixed);
            }
        }
    } else {
        rc = sys_proc_rw_inner((uint32_t)pid, address, data, length,
                               (uint64_t *)(uintptr_t)arg5, write);
    }
    scePthreadMutexUnlock(&g_proc_rw_mutex);
    return rc;
}

long sys_proc_rw_w0(uint64_t pid, uint64_t address, uint64_t length,
                    void *data, uint64_t arg5)
{
    return sys_proc_rw(pid, address, length, data, arg5, 0);
}

long sys_proc_rw_w1(uint64_t pid, uint64_t address, uint64_t length,
                    void *data, uint64_t arg5)
{
    return sys_proc_rw(pid, address, length, data, arg5, 1);
}
