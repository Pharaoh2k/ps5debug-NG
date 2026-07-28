// SPDX-License-Identifier: GPL-3.0-only

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ps5/payload.h>
#include <ps5/kernel.h>
#include "sdk_shim.h"
#include "kern_rw_fast.h"
#include "write_policy.h"

static const uint64_t kr_write_setup_const[2] = { 0x0ULL,                  0x4000000000000000ULL };
static const uint64_t kr_read_setup_const [2] = { 0x4000000040000000ULL,  0x4000000000000000ULL };

static int      kr_rwpair_0;
static int      kr_rwpair_1;
static int      kr_rwpipe_0;
static int      kr_rwpipe_1;
static uint64_t kr_kpipe_addr;
static int      kr_initialized = 0;

static __attribute__((noinline)) int kr_lazy_init(void) {
    payload_args_t *a = payload_get_args();
    if (!a || !a->rwpair || !a->rwpipe || !a->kpipe_addr) return -1;
    kr_rwpair_0   = a->rwpair[0];
    kr_rwpair_1   = a->rwpair[1];
    kr_rwpipe_0   = a->rwpipe[0];
    kr_rwpipe_1   = a->rwpipe[1];
    kr_kpipe_addr = (uint64_t)a->kpipe_addr;
    kr_initialized = 1;
    return 0;
}

typedef unsigned __int128 u128_alias __attribute__((may_alias));

static int kr_setup_field(int fd, void *field, const char *direction,
                          const char *step, intptr_t kaddr, size_t len,
                          int diagnostic)
{
    errno = 0;
    long rc = __crt_syscall(0x69, fd, 0x29, 0x2e, field, 0x14);
    int saved_errno = errno;
    if (diagnostic || rc != 0) {
        klog_printf("[write:pipe] dir=%s kaddr=0x%llx len=%llu "
                    "step=%s rc=%ld errno=%d\n",
                    direction, (unsigned long long)kaddr,
                    (unsigned long long)len, step, rc, saved_errno);
    }
    return rc == 0 ? 0 : -1;
}

__attribute__((target("no-avx")))
static int32_t kernel_copyin_fast_inner(const void *udaddr,
                                        intptr_t kaddr, size_t len)
{
    uint64_t f[7];
    int diagnostic = ps5debug_write_diagnostics_enabled();

    *(u128_alias *)&f[0] = *(const u128_alias *)kr_write_setup_const;
    f[4] = kr_kpipe_addr;
    *(u128_alias *)&f[5] = 0;

    if (kr_setup_field(kr_rwpair_0, &f[4], "in", "flags-address",
                       kaddr, len, diagnostic) != 0)
        return -1;
    f[2] = 0;
    if (kr_setup_field(kr_rwpair_1, &f[0], "in", "flags-value",
                       kaddr, len, diagnostic) != 0)
        return -1;

    f[0] = (uint64_t)kaddr;
    *(u128_alias *)&f[1] = 0;
    f[4] = kr_kpipe_addr + 0x10;
    *(u128_alias *)&f[5] = 0;

    if (kr_setup_field(kr_rwpair_0, &f[4], "in", "data-address",
                       kaddr, len, diagnostic) != 0)
        return -1;
    if (kr_setup_field(kr_rwpair_1, &f[0], "in", "data-value",
                       kaddr, len, diagnostic) != 0)
        return -1;

    errno = 0;
    long rc = __crt_syscall(SYS_write, kr_rwpipe_1,
                            (uint64_t)udaddr, (uint64_t)len);
    int saved_errno = errno;
    if (diagnostic || rc != (long)len) {
        klog_printf("[write:pipe] dir=in kaddr=0x%llx len=%llu "
                    "step=transfer rc=%ld errno=%d\n",
                    (unsigned long long)kaddr, (unsigned long long)len,
                    rc, saved_errno);
    }
    return rc == (long)len ? 0 : -1;
}

__attribute__((target("no-avx")))
static int32_t kernel_copyout_fast_inner(intptr_t kaddr,
                                         void *udaddr, size_t len)
{
    uint64_t f[7];
    int diagnostic = 0;

    *(u128_alias *)&f[0] = *(const u128_alias *)kr_read_setup_const;
    f[4] = kr_kpipe_addr;
    *(u128_alias *)&f[5] = 0;

    if (kr_setup_field(kr_rwpair_0, &f[4], "out", "flags-address",
                       kaddr, len, diagnostic) != 0)
        return -1;
    f[2] = 0;
    if (kr_setup_field(kr_rwpair_1, &f[0], "out", "flags-value",
                       kaddr, len, diagnostic) != 0)
        return -1;

    f[0] = (uint64_t)kaddr;
    *(u128_alias *)&f[1] = 0;
    f[4] = kr_kpipe_addr + 0x10;
    *(u128_alias *)&f[5] = 0;

    if (kr_setup_field(kr_rwpair_0, &f[4], "out", "data-address",
                       kaddr, len, diagnostic) != 0)
        return -1;
    if (kr_setup_field(kr_rwpair_1, &f[0], "out", "data-value",
                       kaddr, len, diagnostic) != 0)
        return -1;

    errno = 0;
    long rc = __crt_syscall(SYS_read, kr_rwpipe_0,
                            udaddr, (uint64_t)len);
    int saved_errno = errno;
    if (diagnostic || rc != (long)len) {
        klog_printf("[write:pipe] dir=out kaddr=0x%llx len=%llu "
                    "step=transfer rc=%ld errno=%d\n",
                    (unsigned long long)kaddr, (unsigned long long)len,
                    rc, saved_errno);
    }
    return rc == (long)len ? 0 : -1;
}

static int32_t kernel_copyin_fast_normalized(const void *udaddr,
                                             intptr_t kaddr, size_t len)
{
    if (len == 0
        || !ps5debug_write_needs_prefix((uint64_t)kaddr))
        return kernel_copyin_fast_inner(udaddr, kaddr, len);
    if (!udaddr || len == SIZE_MAX) return -1;

    uint8_t *prefixed = (uint8_t *)malloc(len + 1);
    if (!prefixed) return -1;
    int32_t rc = kernel_copyout_fast_inner(kaddr - 1, prefixed, 1);
    if (rc == 0) {
        uint8_t leading = prefixed[0];
        memcpy(prefixed + 1, udaddr, len);
        if (ps5debug_write_diagnostics_enabled()) {
            klog_printf("[write:pipe] dir=in kaddr=0x%llx len=%llu "
                        "step=prefix-normalize shifted=0x%llx shifted-len=%llu\n",
                        (unsigned long long)kaddr, (unsigned long long)len,
                        (unsigned long long)(kaddr - 1),
                        (unsigned long long)(len + 1));
        }
        rc = kernel_copyin_fast_inner(prefixed, kaddr - 1, len + 1);
        uint8_t observed = leading ^ 0xFFu;
        if (rc == 0
            && (kernel_copyout_fast_inner(kaddr - 1, &observed, 1) != 0
                || observed != leading)) {
            klog_printf("[write:pipe] dir=in kaddr=0x%llx len=%llu "
                        "prefix-preserve failed expected=%02x actual=%02x\n",
                        (unsigned long long)kaddr, (unsigned long long)len,
                        leading, observed);
            rc = -1;
        }
    }
    free(prefixed);
    return rc;
}

static int32_t kernel_copyout_fast_normalized(intptr_t kaddr,
                                              void *udaddr, size_t len)
{
    if (len == 0
        || !ps5debug_write_needs_prefix((uint64_t)kaddr))
        return kernel_copyout_fast_inner(kaddr, udaddr, len);
    if (!udaddr || len == SIZE_MAX) return -1;

    uint8_t *prefixed = (uint8_t *)malloc(len + 1);
    if (!prefixed) return -1;
    if (ps5debug_write_diagnostics_enabled()) {
        klog_printf("[write:pipe] dir=out kaddr=0x%llx len=%llu "
                    "step=prefix-normalize shifted=0x%llx shifted-len=%llu\n",
                    (unsigned long long)kaddr, (unsigned long long)len,
                    (unsigned long long)(kaddr - 1),
                    (unsigned long long)(len + 1));
    }
    int32_t rc =
        kernel_copyout_fast_inner(kaddr - 1, prefixed, len + 1);
    if (rc == 0) memcpy(udaddr, prefixed + 1, len);
    free(prefixed);
    return rc;
}

int32_t kernel_copyin_fast(const void *udaddr, intptr_t kaddr, size_t len)
{
    if (!kr_initialized && kr_lazy_init() != 0) return -1;
    return kernel_copyin_fast_normalized(udaddr, kaddr, len);
}

int32_t kernel_copyout_fast(intptr_t kaddr, void *udaddr, size_t len)
{
    if (!kr_initialized && kr_lazy_init() != 0) return -1;
    return kernel_copyout_fast_normalized(kaddr, udaddr, len);
}

intptr_t kernel_get_proc_fast(pid_t pid)
{
    uint64_t cur     = 0;
    uint64_t next    = 0;
    uint32_t cur_pid = 0;

    if (kernel_copyout_fast((intptr_t)KERNEL_ADDRESS_ALLPROC, &cur, 8) != 0) return 0;

    while (cur != 0) {
        if (kernel_copyout_fast((intptr_t)(cur + 0xBC), &cur_pid, 4) != 0) return 0;
        if ((int32_t)cur_pid == pid) return (intptr_t)cur;
        if (kernel_copyout_fast((intptr_t)cur, &next, 8) != 0) return 0;
        cur = next;
    }
    return 0;
}

intptr_t kernel_get_proc_ucred_fast(pid_t pid)
{
    uint64_t cur     = 0;
    uint64_t next    = 0;
    uint32_t cur_pid = 0;
    uint64_t ucred   = 0;

    if (kernel_copyout_fast((intptr_t)KERNEL_ADDRESS_ALLPROC, &cur, 8) != 0) return 0;
    if (cur == 0) return 0;

    while (cur != 0) {
        if (kernel_copyout_fast((intptr_t)(cur + 0xBC), &cur_pid, 4) != 0) return 0;
        if ((int32_t)cur_pid == pid) {
            if (kernel_copyout_fast((intptr_t)(cur + 0x40), &ucred, 8) != 0) return 0;
            return (intptr_t)ucred;
        }
        if (kernel_copyout_fast((intptr_t)cur, &next, 8) != 0) return 0;
        cur = next;
    }
    return 0;
}

uint64_t kernel_get_ucred_authid_fast(pid_t pid)
{
    uint64_t authid = 0;
    intptr_t ucred  = kernel_get_proc_ucred_fast(pid);
    if (ucred == 0) return 0;
    if (kernel_copyout_fast(ucred + 0x58, &authid, sizeof(authid)) != 0) return 0;
    return authid;
}

int32_t kernel_set_ucred_authid_fast(pid_t pid, uint64_t new_authid)
{
    intptr_t ucred = kernel_get_proc_ucred_fast(pid);
    if (ucred == 0) return -1;
    return kernel_copyin_fast(&new_authid, ucred + 0x58, sizeof(new_authid));
}

int32_t kernel_get_ucred_caps_fast(pid_t pid, uint8_t caps[16])
{
    intptr_t ucred = kernel_get_proc_ucred_fast(pid);
    if (ucred == 0) return -1;
    if (kernel_copyout_fast(ucred + 0x60, caps, 0x10) != 0) return -1;
    return 0;
}

int32_t kernel_set_ucred_caps_fast(pid_t pid, const uint8_t caps[16])
{
    intptr_t ucred = kernel_get_proc_ucred_fast(pid);
    if (ucred == 0) return -1;
    if (kernel_copyin_fast(caps, ucred + 0x60, 0x10) != 0) return -1;
    return 0;
}

void *kernel_get_proc_struct_fast(uint32_t pid)
{
    void *result = (void *)0;
    if (pid != 0) {
        intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
        if (kproc != 0) {
            void *buf = malloc(0xC90);
            if (buf && kernel_copyout_fast(kproc, buf, 0xC90) == 0)
                result = buf;
            else if (buf) {
                free(buf);
            }
        }
    }
    return result;
}

int kern_setup_sprx_dispatch_fast(int pid, int sprx_handle,
                                   void *buf1, void *buf2)
{
    (void)kernel_get_proc_fast(pid);
    intptr_t kproc = kernel_get_proc_fast(pid);
    if (kproc == 0) return 0;

    uint64_t kaddr;
    if (kernel_copyout_fast((intptr_t)(kproc + 0x3E8), &kaddr, 8) != 0)
        return 0;

    uint8_t *match = (uint8_t *)buf2 + 0x28;
    uint64_t want  = (uint64_t)(uint32_t)sprx_handle;

    do {
        if (kernel_copyout_fast((intptr_t)kaddr, &kaddr, 8) != 0) return 0;
        if (kaddr == 0) return 0;
        if (kernel_copyout_fast((intptr_t)(kaddr + 0x28), match, 8) != 0)
            return 0;
    } while (*(uint64_t *)match != want);

    if (kernel_copyout_fast((intptr_t)kaddr, buf2, 0x180) != 0) return 0;

    int32_t rc = kernel_copyout_fast(
        (intptr_t)*(uint64_t *)((uint8_t *)buf2 + 0x148),
        buf1, 0x120);
    return (int)((uint32_t)~rc >> 31);
}

uint64_t kernel_dynlib_resolve_fast(int pid, int module_sel, const char *nid)
{
    uint8_t  dispatch_table[0x120] __attribute__((aligned(8)));
    uint8_t  module_record[0x180]  __attribute__((aligned(8)));
    uint8_t  entry[0x18]           __attribute__((aligned(8)));
    uint8_t  nid_read[0x0C];

    if (kern_setup_sprx_dispatch_fast(pid, module_sel,
                                       dispatch_table, module_record) == 0)
        return 0;

    uint64_t kaddr_table = *(uint64_t *)(dispatch_table + 0x28);
    uint64_t table_size  = *(uint64_t *)(dispatch_table + 0x30);
    uint64_t nid_strbase = *(uint64_t *)(dispatch_table + 0x38);
    uint64_t module_base = *(uint64_t *)(module_record  + 0x30);

    uint64_t end = kaddr_table + table_size;
    if (kaddr_table >= end) return 0;

    for (uint64_t cur = kaddr_table; cur < end; cur += 0x18) {
        if (kernel_copyout_fast((intptr_t)cur, entry, 0x18) != 0) return 0;

        uint32_t off = *(uint32_t *)entry;
        if (kernel_copyout_fast((intptr_t)((uint64_t)off + nid_strbase),
                                 nid_read, 0x0C) != 0) return 0;

        int matched = 0;
        for (int i = 0; i <= 10; i++) {
            uint8_t want = (uint8_t)nid[i];
            uint8_t got  = nid_read[i];
            if (want != got) { matched = -1; break; }
            if (want == 0)   { matched = 1;  break; }
            if (i == 10)     { matched = 1;  break; }
        }
        if (matched == 1)
            return *(uint64_t *)(entry + 0x08) + module_base;
    }
    return 0;
}

uint64_t kernel_dynlib_mapbase_addr_by_proc_fast(void *proc, unsigned int sel)
{
    uint64_t cur = (uint64_t)proc + 0x3E8;
    if (kernel_copyout_fast((intptr_t)cur, &cur, 8) != 0) return (uint64_t)-1;
    if (kernel_copyout_fast((intptr_t)cur, &cur, 8) != 0) return (uint64_t)-1;

    while (cur != 0) {
        uint32_t entry_sel = 0xFFFFFFFFu;
        if (kernel_copyout_fast((intptr_t)(cur + 0x28), &entry_sel, 4) != 0)
            return (uint64_t)-1;
        if (entry_sel == 0xFFFFFFFFu) return (uint64_t)-1;

        if (entry_sel == sel) {
            uint64_t mapbase = 0;
            kernel_copyout_fast((intptr_t)(cur + 0x30), &mapbase, 8);
            return mapbase;
        }
        if (kernel_copyout_fast((intptr_t)cur, &cur, 8) != 0)
            return (uint64_t)-1;
    }

    uint64_t fallback = 0;
    kernel_copyout_fast((intptr_t)0x30, &fallback, 8);
    return fallback;
}
