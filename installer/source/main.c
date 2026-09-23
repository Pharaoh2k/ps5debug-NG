// SPDX-License-Identifier: GPL-3.0-only

#include <stdint.h>
#include "sdk_shim.h"

extern void port_outer_init_mutexes(void);
extern int  find_proc_pid_by_name(const char *name);
extern int  sys_proc_call_remote_func(int pid, void *elf_buf,
                                       uint64_t a3_unused, void *thread_name);

extern const uint8_t  embedded_inner_start[];
extern const uint8_t  embedded_inner_end[];
extern const uint64_t embedded_inner_size;

#define GUARD_SYS_close    6
#define GUARD_SYS_socket   97
#define GUARD_SYS_connect  98
#define PS5DEBUG_PORT      744

struct guard_sockaddr_in {
    uint8_t  sin_len;
    uint8_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

static void guard_notify(const char *msg)
{
    typedef struct { char useless1[45]; char message[3075]; } req_t;
    req_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static int ps5debug_already_running(void)
{
    long fd = ps5debug_syscall(GUARD_SYS_socket, 2 , 1 ,
                               0, 0, 0, 0);
    if (fd < 0) return 0;

    struct guard_sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_len    = 0x10;
    sa.sin_family = 2;
    sa.sin_port   = (uint16_t)((PS5DEBUG_PORT << 8) | (PS5DEBUG_PORT >> 8));
    sa.sin_addr   = 0x0100007Fu;

    long rc = ps5debug_syscall(GUARD_SYS_connect, fd, (long)&sa, 0x10, 0, 0, 0);
    ps5debug_syscall(GUARD_SYS_close, fd, 0, 0, 0, 0, 0);
    return (rc == 0);
}

static int unlock_target_syscall_filter(int pid)
{
    intptr_t kproc = kernel_get_proc((pid_t)pid);
    if (!kproc) return -1;

    intptr_t filter_addr = 0;
    if (kernel_copyout(kproc + 0x3e8, &filter_addr, sizeof(filter_addr)) < 0)
        return -1;
    if (!filter_addr) return -1;

    unsigned long uaddr;
    uaddr = 0UL;
    if (kernel_copyin(&uaddr, filter_addr + 0xf0, sizeof(uaddr)) < 0) return -1;
    uaddr = (unsigned long)-1L;
    if (kernel_copyin(&uaddr, filter_addr + 0xf8, sizeof(uaddr)) < 0) return -1;

    return 0;
}

static int install_kernel_patch(void)
{
    intptr_t kbase = (intptr_t)KERNEL_ADDRESS_DATA_BASE;

    uint32_t raw = kernel_get_fw_version();
    uint32_t fw  = raw & 0xffff0000u;

    klog_printf("port_outer: kpatch FW raw=0x%x kbase=0x%lx\n",
                raw, (unsigned long)kbase);

    intptr_t patch_addr;
    const char *fw_label;
    switch (fw) {
    case 0x3000000u: case 0x3100000u: case 0x3200000u: case 0x3210000u:   /* 3.00 3.10 3.20 3.21 */
        patch_addr = kbase + 0x6466498ULL;
        fw_label = "FW 3.x";
        break;
    case 0x4020000u:                                                      /* 4.02 */
        patch_addr = kbase + 0x6505498ULL;
        fw_label = "FW 4.0";
        break;
    case 0x4000000u: case 0x4030000u: case 0x4500000u: case 0x4510000u:   /* 4.00 4.03 4.50 4.51 */
        patch_addr = kbase + 0x6506498ULL;
        fw_label = "FW 4.x (incl. 4.51)";
        break;
    case 0x5000000u: case 0x5020000u: case 0x5100000u: case 0x5500000u:   /* 5.00 5.02 5.10 5.50 */
        patch_addr = kbase + 0x6646710ULL;
        fw_label = "FW 5.x";
        break;
    case 0x6000000u: case 0x6020000u: case 0x6500000u:                    /* 6.00 6.02 6.50 */
        patch_addr = kbase + 0x6596910ULL;
        fw_label = "FW 6.x";
        break;
    case 0x7000000u:  case 0x7010000u: case 0x7010100u:  case 0x7200000u:
    case 0x7400000u:  case 0x7600000u: case 0x7610000u:                     /* 7.00 7.01 7.01.01 7.20 7.40 7.60 7.61*/
        patch_addr = kbase + 0xAC8088ULL;
        fw_label = "FW 7.x";
        break;
    case 0x8000000u:  case 0x8200000u:  case 0x8400000u:  case 0x8600000u:  /* 8.00  8.20  8.40  8.60 */
        patch_addr = kbase + 0xAC3088ULL;
        fw_label = "FW 8.x";
        break;
    case 0x9000000u:                                                        /* 9.00 */
        patch_addr = kbase + 0xD72088ULL;
        fw_label = "FW 9.00";
        break;
    case 0x9050000u:  case 0x9200000u:
    case 0x9400000u:  case 0x9600000u:                                      /* 9.05  9.20  9.40  9.60 */
        patch_addr = kbase + 0xD73088ULL;
        fw_label = "FW 9.x";
        break;
    case 0x10000000u: case 0x10010000u: case 0x10200000u:
    case 0x10400000u: case 0x10600000u:                                     /* 10.00 10.01 10.20 10.40 10.60 */
        patch_addr = kbase + 0xD79088ULL;
        fw_label = "FW 10.x";
        break;
    case 0x11000000u: case 0x11200000u:
    case 0x11400000u: case 0x11600000u:                                     /* 11.00 11.20 11.40 11.60 */
        patch_addr = kbase + 0xD8C088ULL;
        fw_label = "FW 11.x";
        break;
    case 0x12000000u: case 0x12020000u: case 0x12200000u:
    case 0x12400000u: case 0x12600000u: case 0x12700000u:                   /* 12.00 12.02 12.20 12.40 12.60 12.70 */
        patch_addr = kbase + 0xD83088ULL;
        fw_label = "FW 12.x";
        break;
    case 0x13000000u: case 0x13200000u:
    case 0x13400000u: case 0x13420000u:                                     /* 13.00 13.20 13.40 13.42 */
        patch_addr = kbase + 0xD99088ULL;
        fw_label = "FW 13.0x-13.4x";
        break;
    case 0x13600000u:                                                       /* 13.60 */
        patch_addr = kbase + 0xD9C088ULL;
        fw_label = "FW 13.60";
        break;
    default:
        klog_printf("port_outer: kpatch SKIP - unsupported FW magic 0x%x\n", fw);
        return -1;
    }
    klog_printf("port_outer: kpatch %s recognized; addr=0x%lx\n",
                fw_label, (unsigned long)patch_addr);

    uint8_t scratch[16];
    if (kernel_copyout(patch_addr, scratch, 16) < 0) {
        klog_puts("port_outer: kpatch READ failed\n");
        return -1;
    }
    klog_printf("port_outer: kpatch read byte[1]=0x%02x (will OR with 3)\n",
                scratch[1]);

    if ((scratch[1] & 3) == 3) {
        klog_puts("port_outer: kpatch already set by jailbreak\n");
        return 0;
    }

    scratch[1] |= 3;

    if (kernel_copyin(scratch, patch_addr, 16) < 0) {
        klog_puts("port_outer: kpatch WRITE failed\n");
        return -1;
    }
    klog_printf("port_outer: kpatch WRITE OK; byte[1] now 0x%02x\n", scratch[1]);

    uint8_t verify[16];
    if (kernel_copyout(patch_addr, verify, 16) < 0) {
        klog_puts("port_outer: kpatch verify read failed\n");
        return -1;
    }
    klog_printf("port_outer: kpatch verify byte[1]=0x%02x stuck=%s\n",
                verify[1], ((verify[1] & 3) == 3) ? "YES" : "NO");
    return ((verify[1] & 3) == 3) ? 0 : -1;
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    port_outer_init_mutexes();

    if (ps5debug_already_running()) {
        klog_puts("port_outer: ps5debug already running on port 744 - install aborted\n");
        guard_notify("ps5debug-NG is already running - injection skipped");
        payload_exit(0);
        return 0;
    }

    klog_printf("port_outer: embedded inner ELF = %lu B\n",
                (unsigned long)embedded_inner_size);

    int pid = find_proc_pid_by_name("SceShellCore");
    if (pid < 0) {
        klog_puts("port_outer: SceShellCore not found in allproc walk\n");
        payload_exit(1);
        return 1;
    }
    klog_printf("port_outer: SceShellCore pid = %d\n", pid);

    if (install_kernel_patch() == 0) {
        klog_puts("port_outer: kernel patch installed\n");
    } else {
        klog_puts("port_outer: WARNING - kernel patch failed; PT_ATTACH on games will not work\n");
    }

    if (unlock_target_syscall_filter(pid) == 0) {
        klog_puts("port_outer: SceShellCore syscall_filter unlocked\n");
    } else {
        klog_puts("port_outer: WARNING - syscall_filter unlock failed\n");
    }

    long rc = sys_proc_call_remote_func(pid,
                                        (void *)embedded_inner_start,
                                        0,
                                        (void *)"libSceShareInternal.native.sprx");
    klog_printf("port_outer: sys_proc_call_remote_func rc = %ld\n", rc);

    if (rc != 0) {
        klog_puts("port_outer: inject FAILED\n");
        payload_exit(2);
        return 2;
    }

    klog_puts("port_outer: inject OK - SceShellCore now hosts inner\n");
    payload_exit(0);
    return 0;
}
