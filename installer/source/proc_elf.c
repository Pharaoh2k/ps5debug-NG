// SPDX-License-Identifier: GPL-3.0-only

#include "protocol.h"
#include "sdk_shim.h"
#include "net.h"
#include "proc.h"
#include "kern_rw_fast.h"
#include <stdarg.h>
#include <sys/mman.h>

extern uint64_t proc_call_remote_sys(int pid, int sysno, ...);
extern int      kern_ptrace_attach_and_wait(int pid);
extern int      pt_detach(int pid);
extern void    *freebsd_mmap(unsigned long pid, void *addr, unsigned long length,
                              int prot, int flags, int fd, long offset);
extern int      freebsd_munmap(int pid, unsigned long addr, unsigned long len);

static long pt_read_i(int pid, void *target_addr) {
    return ptrace_elev(2 , pid, target_addr, 0);
}

static long pt_write_i(int pid, void *target_addr, int data) {
    return ptrace_elev(5 , pid, target_addr, data);
}

static int pt_io(int pid, void *target_addr, uint64_t data) {
    uint64_t buf[5];
    buf[0] = data;
    *(uint32_t *)&buf[1] = 2;
    buf[2] = (uint64_t)target_addr;
    buf[3] = (uint64_t)&buf[0];
    buf[4] = 8;
    return (int)ptrace_elev(0xC , pid, &buf[1], 0);
}

int ptrace_io_write_d(int pid, void *src_local, void *dst_target, uint64_t len) {
    uint64_t buf[5];
    *(uint32_t *)&buf[1] = 2;
    buf[2] = (uint64_t)dst_target;
    buf[3] = (uint64_t)src_local;
    buf[4] = len;
    return (int)ptrace_elev(0xC , pid, &buf[1], 0);
}

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

__attribute__((noinline))
static int proc_rpc_call_via_ptrace(int pid, int sysno, ...)
{
    uint8_t  saved_regs   [PCRK_SIZEOF_REG];
    uint8_t  modified_regs[PCRK_SIZEOF_REG];

    uint64_t nid_addr = kernel_dynlib_resolve_fast(pid, 1, NID_LIBKERNEL_SYSCALL);
    if (nid_addr == 0) {
        nid_addr = kernel_dynlib_resolve_fast(pid, 0x2001, NID_LIBKERNEL_SYSCALL);
        if (nid_addr == 0) return -1;
    }

    if (ptrace_elev(0x21 , pid, saved_regs, 0) != 0)
        return -1;

    nid_addr += 0xA;
    memcpy(modified_regs, saved_regs, PCRK_SIZEOF_REG);

    *(uint64_t *)(modified_regs + PCRK_R_RIP) = nid_addr;
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
        return -1;

    uint64_t saved_rsp = *(uint64_t *)(saved_regs + PCRK_R_RSP);

    while (*(uint64_t *)(modified_regs + PCRK_R_RSP) <= saved_rsp) {
        if (ptrace_elev(9 , pid, (void *)(uintptr_t)1, 0) != 0)
            return -1;
        if ((int)waitpid(pid, 0, 0) < 0)
            return -1;
        if (ptrace_elev(0x21 , pid, modified_regs, 0) != 0)
            return -1;
    }

    int set_rc = (int)ptrace_elev(0x22 , pid, saved_regs, 0);
    int rax = *(int *)(modified_regs + PCRK_R_RAX);
    return (set_rc ? -1 : rax);
}

__attribute__((noinline))
static uint64_t proc_remote_call_via_ptrace(int pid, uint64_t addr, ...)
{
    uint8_t  saved_regs   [PCRK_SIZEOF_REG];
    uint8_t  modified_regs[PCRK_SIZEOF_REG];
    uint64_t result = (uint64_t)-1;

    if (ptrace_elev(0x21 , pid, saved_regs, 0) != 0)
        return result;

    memcpy(modified_regs, saved_regs, PCRK_SIZEOF_REG);
    *(uint64_t *)(modified_regs + PCRK_R_RIP) = addr;

    {
        va_list ap;
        va_start(ap, addr);
        *(uint64_t *)(modified_regs + PCRK_R_RDI) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RSI) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RDX) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_RCX) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R8 ) = va_arg(ap, uint64_t);
        *(uint64_t *)(modified_regs + PCRK_R_R9 ) = va_arg(ap, uint64_t);
        va_end(ap);
    }

    if (ptrace_elev(0x22 , pid, modified_regs, 0) != 0)
        return result;

    uint64_t saved_rsp = *(uint64_t *)(saved_regs + PCRK_R_RSP);

    while (*(uint64_t *)(modified_regs + PCRK_R_RSP) <= saved_rsp) {
        if (ptrace_elev(0x9 , pid, (void *)1, 0) != 0)
            return result;
        if ((int)waitpid(pid, (int *)0, 0) < 0)
            return result;
        if (ptrace_elev(0x21 , pid, modified_regs, 0) != 0)
            return result;
    }

    if (ptrace_elev(0x22 , pid, saved_regs, 0) != 0)
        return result;

    return *(uint64_t *)(modified_regs + PCRK_R_RAX);
}

static int kern_close_thunk(int pid, unsigned int fd) {
    return proc_rpc_call_via_ptrace(pid, 6, fd);
}

static int kern_jitshm_alias(int pid, unsigned int a, unsigned int b) {
    return proc_rpc_call_via_ptrace(pid, 0x216, a, b);
}

static int kern_jitshm_create(int pid, unsigned long a, unsigned long b,
                               unsigned int c) {
    return proc_rpc_call_via_ptrace(pid, 0x215, a, b, c);
}

static int kern_syscall_socket(int pid, unsigned int family, unsigned int type,
                                unsigned int protocol) {
    return proc_rpc_call_via_ptrace(pid, 0x61, family, type, protocol);
}

static int kern_setsockopt(int pid, unsigned int s, unsigned int level,
                            unsigned int optname, unsigned long optval,
                            unsigned int optlen) {
    return proc_rpc_call_via_ptrace(pid, 0x69, s, level, optname, optval, optlen);
}

static long sys_mprotect(uint32_t pid, uint64_t addr, uint64_t length,
                          uint64_t prot) {
    return proc_rpc_call_via_ptrace((int)pid, 0x4a, addr, length, prot);
}

static void *pf_kernel_get_proc_file(int pid, int fd)
{
    uint64_t cur     = 0;
    uint64_t next    = 0;
    uint32_t cur_pid = 0;
    uint64_t p_fd, fd_files, fde_file, file;

    if (kernel_copyout_fast((intptr_t)KERNEL_ADDRESS_ALLPROC, &cur, 8) != 0) return 0;
    if (cur == 0) return 0;

    while (cur != 0) {
        if (kernel_copyout_fast(cur + 0xBC, &cur_pid, 4) != 0) return 0;
        if ((int32_t)cur_pid == pid) {
            if (kernel_copyout_fast(cur + 0x48, &p_fd, 8) != 0) return 0;
            if (kernel_copyout_fast(p_fd, &fd_files, 8) != 0) return 0;
            if (kernel_copyout_fast(fd_files + 8 + (uint64_t)0x30 * (uint32_t)fd,
                                     &fde_file, 8) != 0) return 0;
            if (kernel_copyout_fast(fde_file, &file, 8) != 0) return 0;
            return (void *)file;
        }
        if (kernel_copyout_fast(cur, &next, 8) != 0) return 0;
        cur = next;
    }
    return 0;
}

static int pf_kernel_overlap_sockets(int pid, int sock_a, int sock_b)
{
    uint64_t var_48 = 0;
    uint64_t src    = 0;
    uint64_t v9;
    uint64_t fd_data;

    if (!(fd_data = (uint64_t)pf_kernel_get_proc_file(pid, sock_a))) return -1;
    if (kernel_copyout_fast(fd_data, &var_48, 4) != 0) return -1;
    *(uint32_t *)&var_48 = 0x100;
    if (kernel_copyin_fast(&var_48, (intptr_t)fd_data, 4) != 0) return -1;

    if (!(fd_data = (uint64_t)pf_kernel_get_proc_file(pid, sock_a))) return -1;
    if (kernel_copyout_fast(fd_data + 0x18, &src, 8) != 0) return -1;
    if (kernel_copyout_fast(src + 0x120, &var_48, 8) != 0) return -1;
    if ((v9 = var_48) == 0) return -1;

    if (!(fd_data = (uint64_t)pf_kernel_get_proc_file(pid, sock_b))) return -1;
    if (kernel_copyout_fast(fd_data, &var_48, 4) != 0) return -1;
    *(uint32_t *)&var_48 = 0x100;
    if (kernel_copyin_fast(&var_48, (intptr_t)fd_data, 4) != 0) return -1;

    if (!(fd_data = (uint64_t)pf_kernel_get_proc_file(pid, sock_b))) return -1;
    if (kernel_copyout_fast(fd_data + 0x18, &src, 8) != 0) return -1;
    if (kernel_copyout_fast(src + 0x120, &var_48, 8) != 0) return -1;
    if (var_48 == 0) return -1;

    var_48 += 0x10;
    if (kernel_copyin_fast(&var_48, (intptr_t)(v9 + 0x10), 8) != 0) return -1;

    *(uint32_t *)&src = 0x13370000u;
    if (kernel_copyin_fast(&src, (intptr_t)(v9 + 0xC0), 4) != 0) return -1;
    return 0;
}

static int proc_resolve_call_nid_Jp7F(int pid, void *scratch)
{
    const char *nid = "-Jp7F+pXxNg";
    uint64_t addr = kernel_dynlib_resolve_fast(pid, 1, nid);
    if (addr == 0)
        addr = kernel_dynlib_resolve_fast(pid, 0x2001, nid);
    return (int)proc_remote_call_via_ptrace(pid, addr, (uint64_t)(uintptr_t)scratch);
}

static void compute_fw_vmmap_adjustments(uint64_t *out_nentries_adj,
                                          uint64_t *out_name_adj) {
    uint32_t fw = kernel_get_fw_version();
    int write_adj = ((fw & 0xffff0000u) >= 0x6000000u) ? 1 : 0;
    *out_nentries_adj = write_adj ? 8    : 0;
    *out_name_adj     = write_adj ? 0xE  : 0;
}

static uint64_t kernel_get_vmem_entry_by_name(int pid, const char *name)
{
    if (!name) return (uint64_t)-1;

    uint64_t nentries_adj, name_adj;
    compute_fw_vmmap_adjustments(&nentries_adj, &name_adj);

    uint64_t vmspace_kaddr = 0;
    uint8_t  vmspace_buf[0x350];
    uint8_t  entry_buf  [0x1c0];
    uint8_t  cmp_buf    [0x20];
    uint64_t cur_proc  = 0;
    uint64_t next_proc = 0;
    int32_t  cur_pid   = 0;

    if (kernel_copyout_fast((intptr_t)KERNEL_ADDRESS_ALLPROC, &cur_proc, 8) != 0) return (uint64_t)-1;
    if (cur_proc == 0) return (uint64_t)-1;

    for (;;) {
        if (kernel_copyout_fast(cur_proc + 0xBC, &cur_pid, 4) != 0) return (uint64_t)-1;
        if (cur_pid == pid) break;
        if (kernel_copyout_fast(cur_proc, &next_proc, 8) != 0) return (uint64_t)-1;
        cur_proc = next_proc;
        if (cur_proc == 0) return (uint64_t)-1;
    }

    if (kernel_copyout_fast(cur_proc + 0x200, &vmspace_kaddr, 8) != 0) return (uint64_t)-1;

    memset(vmspace_buf, 0, 0x350);
    if (kernel_copyout_fast(vmspace_kaddr, vmspace_buf, 0x350) != 0) return (uint64_t)-1;

    int32_t n_entries = *(int32_t *)(vmspace_buf + 0x1A8 + (uintptr_t)nentries_adj);
    if (n_entries <= 0) return (uint64_t)-1;

    uint64_t cur_entry = *(uint64_t *)(vmspace_buf + 8);
    do {
        memset(entry_buf, 0, 0x1c0);
        if (kernel_copyout_fast(cur_entry, entry_buf, 0x1c0) != 0) return (uint64_t)-1;

        memcpy(cmp_buf, entry_buf + 0x142 + (uintptr_t)name_adj, 0x20);

        if (strcmp((const char *)cmp_buf, name) == 0)
            return *(uint64_t *)(entry_buf + 0x20);

        cur_entry = *(uint64_t *)(entry_buf + 8);
    } while (--n_entries != 0);

    return (uint64_t)-1;
}

static int kern_init_dbgctx_at_addr_kern(uint32_t pid, uint64_t addr)
{
    if (addr == 0) return -1;

    uint64_t nentries_adj, name_adj;
    (void)name_adj;
    compute_fw_vmmap_adjustments(&nentries_adj, &name_adj);

    uint64_t cur_proc  = 0;
    uint64_t next_proc = 0;
    uint64_t p_vmspace = 0;
    int      cur_pid   = 0;
    uint8_t  vmspace_buf[0x350];
    uint8_t  entry_buf [0x1c0];
    uint8_t  link_buf  [0x1c0];

    if (kernel_copyout_fast((intptr_t)KERNEL_ADDRESS_ALLPROC, &cur_proc, 8) != 0) return -1;
    if (cur_proc == 0) return -1;

    while (1) {
        if (kernel_copyout_fast(cur_proc + 0xBC, &cur_pid, 4) != 0) return -1;
        if (cur_pid == (int)pid) break;
        if (kernel_copyout_fast(cur_proc, &next_proc, 8) != 0) return -1;
        cur_proc = next_proc;
        if (cur_proc == 0) return -1;
    }

    if (kernel_copyout_fast(cur_proc + 0x200, &p_vmspace, 8) != 0) return -1;

    memset(vmspace_buf, 0, 0x350);
    if (kernel_copyout_fast(p_vmspace, vmspace_buf, 0x350) != 0) return -1;

    int nentries = *(int32_t *)(vmspace_buf + 0x1A8 + (uintptr_t)nentries_adj);
    if (nentries <= 0) return -1;

    uint64_t cur_entry = *(uint64_t *)(vmspace_buf + 8);
    int      idx = 0;
    while (idx < nentries) {
        memset(entry_buf, 0, 0x1c0);
        if (kernel_copyout_fast(cur_entry, entry_buf, 0x1c0) != 0) return -1;

        uint64_t e_start = *(uint64_t *)(entry_buf + 0x20);
        uint64_t e_end   = *(uint64_t *)(entry_buf + 0x28);
        if (e_start <= addr && addr < e_end) {
            uint64_t entry_prev = *(uint64_t *)(entry_buf + 0);
            uint64_t entry_next = *(uint64_t *)(entry_buf + 8);

            memset(link_buf, 0, 0x1c0);
            if (kernel_copyout_fast(entry_prev, link_buf, 0x1c0) != 0) return -1;
            *(uint64_t *)(link_buf + 8) = entry_next;
            if (kernel_copyin_fast(link_buf, (intptr_t)entry_prev, 0x1c0) != 0) return -1;

            if (entry_next == 0) return 0;

            memset(link_buf, 0, 0x1c0);
            if (kernel_copyout_fast(entry_next, link_buf, 0x1c0) != 0) return -1;
            *(uint64_t *)(link_buf + 0) = entry_prev;
            if (kernel_copyin_fast(link_buf, (intptr_t)entry_next, 0x1c0) != 0) return -1;

            int      local_nent = 0;
            uint8_t *nent_local_addr = vmspace_buf + 0x1A8 + (uintptr_t)nentries_adj;
            if (kernel_copyout_fast((intptr_t)nent_local_addr, &local_nent, 4) != 0) return -1;
            local_nent -= 1;
            int rc = kernel_copyin_fast(&local_nent, (intptr_t)nent_local_addr, 4);
            return rc ? -1 : 0;
        }
        cur_entry = *(uint64_t *)(entry_buf + 8);
        idx++;
    }
    return -1;
}

static uint64_t proc_call_remote_sce(int pid)
{
    void *mmap_rv = freebsd_mmap((unsigned long)pid, (void *)0, 0x4000, 7,
                                  0x1002, -1, 0);
    if ((long)mmap_rv == -1L) return 0;
    uint64_t scratch = (uint64_t)mmap_rv;

    int sock_a = kern_syscall_socket(pid, 0x1c, 2, 0x11);
    if (sock_a < 0) return 0;

    {
        uint32_t seed_a[6] = { 0x14, 0x29, 0x3D, 0, 0, 0 };
        if (ptrace_io_write_d((int)pid, seed_a, (void *)(scratch + 0x00), 24))
            return 0;
    }

    if (kern_setsockopt(pid, sock_a, 0x29, 0x19, scratch, 0x18) != 0)
        return 0;

    int sock_b = kern_syscall_socket(pid, 0x1c, 2, 0x11);
    if (sock_b < 0) return 0;

    {
        uint32_t seed_b[5] = { 0, 0, 0, 0, 0 };
        if (ptrace_io_write_d((int)pid, seed_b, (void *)(scratch + 0x00), 20))
            return 0;
    }

    if (kern_setsockopt(pid, sock_b, 0x29, 0x2E, scratch, 0x14) != 0)
        return 0;

    if (pf_kernel_overlap_sockets(pid, sock_a, sock_b) != 0) return 0;

    if (proc_resolve_call_nid_Jp7F(pid, (void *)scratch) != 0) return 0;

    int read_a = (int)pt_read_i(pid, (void *)(scratch + 0x00));
    int read_b = (int)pt_read_i(pid, (void *)(scratch + 0x04));

    uint64_t nid_addr = kernel_dynlib_resolve_fast(pid, 1, "LwG8g3niqwA");
    if (nid_addr == 0)
        nid_addr = kernel_dynlib_resolve_fast(pid, 0x2001, "LwG8g3niqwA");

    int32_t disp = 0;
    sys_proc_rw_w0((uint64_t)pid, nid_addr + 5, 4, &disp, 0);
    nid_addr += (int64_t)disp;
    nid_addr += 9;

    void *fd_data = pf_kernel_get_proc_file(pid, read_a);

    {
        uint64_t hdr[6] = {
            nid_addr,
            scratch + 0x100,
            scratch + 0x200,
            (uint64_t)fd_data,
            (uint64_t)KERNEL_ADDRESS_DATA_BASE,
            scratch + 0x300
        };
        if (ptrace_io_write_d((int)pid, hdr, (void *)(scratch + 0x00), 48))
            return 0;
    }

    {
        uint32_t pair1[2] = { (uint32_t)read_a, (uint32_t)read_b };
        if (ptrace_io_write_d((int)pid, pair1, (void *)(scratch + 0x100), 8))
            return 0;
    }
    {
        uint32_t pair2[2] = { (uint32_t)sock_a, (uint32_t)sock_b };
        if (ptrace_io_write_d((int)pid, pair2, (void *)(scratch + 0x200), 8))
            return 0;
    }
    {
        uint32_t zero = 0;
        if (ptrace_io_write_d((int)pid, &zero, (void *)(scratch + 0x300), 4))
            return 0;
    }

    return scratch;
}

#undef  PAGE_MASK
#define PF_PAGE_MASK 0xFFFFFFFFFFFFC000ULL
#define PAGE_ROUND_UP(x) (((x) + 0x3FFFULL) & PF_PAGE_MASK)
#define PAGE_TRUNC(x) ((x) & PF_PAGE_MASK)

static inline int elf_pflags_to_prot(uint32_t p_flags) {

    return ((p_flags & 1) ? 4 : 0)
         | ((p_flags & 2) ? 2 : 0)
         | ((p_flags & 4) ? 1 : 0);
}

long proc_load_elf_inject(uint32_t pid, char *elf_buf, const char *thread_name)
{
    if (elf_buf[0] != 0x7F) return -1;
    if (elf_buf[1] != 'E')  return -1;
    if (elf_buf[2] != 'L')  return -1;
    if (elf_buf[3] != 'F')  return -1;

    uint64_t e_entry = *(uint64_t *)(elf_buf + 0x18);
    uint64_t e_phoff = *(uint64_t *)(elf_buf + 0x20);
    uint64_t e_shoff = *(uint64_t *)(elf_buf + 0x28);
    uint16_t e_type  = *(uint16_t *)(elf_buf + 0x10);
    uint16_t e_phnum = *(uint16_t *)(elf_buf + 0x38);
    uint16_t e_shnum = *(uint16_t *)(elf_buf + 0x3C);

    char *phdr_base = elf_buf + e_phoff;
    char *shdr_base = elf_buf + e_shoff;

    uint64_t min_vaddr = ~0ULL;
    uint64_t max_endaddr = 0;
    if (e_phnum) {
        uint64_t end = (uint64_t)e_phnum * 56;
        for (uint64_t off = 0; off != end; off += 56) {
            uint32_t p_type  = *(uint32_t *)(phdr_base + off + 0);
            if (p_type != 1) continue;
            uint64_t p_memsz = *(uint64_t *)(phdr_base + off + 40);
            if (p_memsz == 0) continue;
            uint64_t p_vaddr = *(uint64_t *)(phdr_base + off + 16);
            if (p_vaddr < min_vaddr) min_vaddr = p_vaddr;
            uint64_t segend = p_vaddr + p_memsz;
            if (segend > max_endaddr) max_endaddr = segend;
        }
    }

    int mmap_flags;
    uint64_t base_request;
    uint64_t min_aligned = PAGE_TRUNC(min_vaddr);
    if (e_type == 2) {
        mmap_flags = 0x1012;
        base_request = min_aligned;
    } else if (e_type == 3) {
        mmap_flags = 0x1002;
        base_request = 0;
    } else {
        return 0;
    }

    if (thread_name) {
        long kctx_rc = (long)kernel_get_vmem_entry_by_name((int)pid, thread_name);
        if (kctx_rc == -1) return -1;
        base_request = (uint64_t)kctx_rc;
    }

    uint64_t total_size = PAGE_ROUND_UP(max_endaddr) - min_aligned;
    void *base_p = freebsd_mmap((unsigned long)pid, (void *)base_request,
                                 (unsigned long)total_size, 0,
                                 mmap_flags, -1, 0);
    if ((intptr_t)base_p == -1) return 0;
    uint64_t base_addr = (uint64_t)base_p;

    uint8_t *image = (uint8_t *)mmap(NULL, (size_t)total_size,
                                      3 ,
                                      0x1002 ,
                                      -1, 0);
    if ((intptr_t)image == -1) goto cleanup_base;
    memset(image, 0, (size_t)total_size);

    if (e_phnum) {
        for (uint16_t i = 0; i < e_phnum; i++) {
            char *ph = phdr_base + (uint64_t)i * 56;
            uint32_t p_type = *(uint32_t *)(ph + 0);
            if (p_type != 1) continue;
            uint64_t p_filesz = *(uint64_t *)(ph + 32);
            if (p_filesz == 0) continue;
            uint64_t p_offset = *(uint64_t *)(ph + 8);
            uint64_t p_vaddr  = *(uint64_t *)(ph + 16);
            memcpy(image + (p_vaddr - min_aligned),
                   elf_buf + p_offset, (size_t)p_filesz);
        }
    }

    if (e_shnum) {
        for (uint16_t i = 0; i < e_shnum; i++) {
            char *sh = shdr_base + (uint64_t)i * 64;
            uint32_t sh_type = *(uint32_t *)(sh + 4);
            if (sh_type != 4) continue;
            uint64_t sh_size = *(uint64_t *)(sh + 0x20);
            if (sh_size < 24) continue;
            uint64_t sh_offset = *(uint64_t *)(sh + 0x18);
            char *rela_base = elf_buf + sh_offset;
            uint64_t nrela = sh_size / 24;
            for (uint64_t j = 0; j < nrela; j++) {
                char *r = rela_base + j * 24;
                uint32_t r_type_lo = *(uint32_t *)(r + 8);
                if (r_type_lo != 8) continue;
                uint64_t r_offset = *(uint64_t *)(r + 0);
                uint64_t r_addend = *(uint64_t *)(r + 16);
                *(uint64_t *)(image + (r_offset - min_aligned)) = base_addr + r_addend;
            }
        }
    }

    if (e_phnum) {
        for (uint16_t i = 0; i < e_phnum; i++) {
            char *ph = phdr_base + (uint64_t)i * 56;
            uint32_t p_type  = *(uint32_t *)(ph + 0);
            if (p_type != 1) continue;
            uint64_t p_memsz = *(uint64_t *)(ph + 40);
            if (p_memsz == 0) continue;
            uint32_t p_flags = *(uint32_t *)(ph + 4);
            uint64_t p_vaddr  = *(uint64_t *)(ph + 16);

            uint64_t aligned_memsz = PAGE_ROUND_UP(p_memsz);
            uint64_t target_addr = base_addr + p_vaddr;

            void *src = image + (p_vaddr - min_aligned);
            int seg_prot = elf_pflags_to_prot(p_flags);

            if (p_flags & 1) {
                int shm_prot = ((p_flags >> 2) & 1) | 6;
                int shm_fd = kern_jitshm_create((int)pid, 0, aligned_memsz,
                                                 (unsigned int)shm_prot);
                if (shm_fd < 0) goto cleanup_base;

                void *exe_addr = freebsd_mmap((unsigned long)pid, (void *)target_addr,
                                               (unsigned long)aligned_memsz,
                                               seg_prot, 0x11,
                                               shm_fd, 0);
                if ((intptr_t)exe_addr == -1) {
                    kern_close_thunk((int)pid, (unsigned int)shm_fd);
                    goto cleanup_base;
                }

                int alias_fd = kern_jitshm_alias((int)pid, (unsigned int)shm_fd, 3);
                if (alias_fd < 0) {
                    kern_close_thunk((int)pid, (unsigned int)shm_fd);
                    goto cleanup_base;
                }

                void *rw_addr = freebsd_mmap((unsigned long)pid, NULL,
                                              (unsigned long)aligned_memsz,
                                              3, 1,
                                              alias_fd, 0);
                if ((intptr_t)rw_addr == -1) {
                    kern_close_thunk((int)pid, (unsigned int)alias_fd);
                    kern_close_thunk((int)pid, (unsigned int)shm_fd);
                    goto cleanup_base;
                }

                if (ptrace_io_write_d((int)pid, src, rw_addr, p_memsz)) {
                    freebsd_munmap((int)pid, (unsigned long)(uintptr_t)rw_addr,
                                    (unsigned long)aligned_memsz);
                    kern_close_thunk((int)pid, (unsigned int)alias_fd);
                    kern_close_thunk((int)pid, (unsigned int)shm_fd);
                    goto cleanup_base;
                }

                freebsd_munmap((int)pid, (unsigned long)(uintptr_t)rw_addr,
                                (unsigned long)aligned_memsz);
                kern_close_thunk((int)pid, (unsigned int)alias_fd);
                kern_close_thunk((int)pid, (unsigned int)shm_fd);
            } else {
                void *seg_addr = freebsd_mmap((unsigned long)pid, (void *)target_addr,
                                               (unsigned long)aligned_memsz,
                                               2, 0x1012, -1, 0);
                if ((intptr_t)seg_addr == -1) goto cleanup_base;
                if (ptrace_io_write_d((int)pid, src, seg_addr, p_memsz))
                    goto cleanup_base;
            }
        }
    }

    if (e_phnum) {
        for (uint16_t i = 0; i < e_phnum; i++) {
            char *ph = phdr_base + (uint64_t)i * 56;
            uint32_t p_type = *(uint32_t *)(ph + 0);
            if (p_type != 1) continue;
            uint64_t p_memsz = *(uint64_t *)(ph + 40);
            if (p_memsz == 0) continue;
            uint32_t p_flags = *(uint32_t *)(ph + 4);
            uint64_t p_vaddr = *(uint64_t *)(ph + 16);
            uint64_t aligned_memsz = PAGE_ROUND_UP(p_memsz);
            uint64_t target_addr = base_addr + p_vaddr;
            int seg_prot = elf_pflags_to_prot(p_flags);
            if (sys_mprotect(pid, target_addr, aligned_memsz,
                              (uint64_t)seg_prot))
                goto cleanup_base;
        }
    }

    if (thread_name) {
        kern_init_dbgctx_at_addr_kern(pid, base_addr + e_entry);
    }

    munmap(image, (size_t)total_size);
    return (long)(base_addr + e_entry);

cleanup_base:

    if (image && (intptr_t)image != -1) munmap(image, (size_t)total_size);
    freebsd_munmap((int)pid, (unsigned long)base_addr, (unsigned long)total_size);
    return 0;
}

#define SPCRF_SIZEOF_REG  0xb0
#define SPCRF_R_RDI       0x40
#define SPCRF_R_RIP       0x88

int sys_proc_call_remote_func(int pid, void *elf_buf, uint64_t a3_unused,
                               void *thread_name)
{
    (void)a3_unused;
    uint8_t  saved_caps[16] __attribute__((aligned(16)));
    uint8_t  saved_regs[SPCRF_SIZEOF_REG] __attribute__((aligned(8)));

    if (kernel_get_ucred_caps_fast(pid, saved_caps)) return -1;

    uint8_t all_ones[16];
    memset(all_ones, 0xFF, 16);
    if (kernel_set_ucred_caps_fast(pid, all_ones)) return -1;

    if (kern_ptrace_attach_and_wait(pid)) {
        kernel_set_ucred_caps_fast(pid, saved_caps);
        return -1;
    }

    if (ptrace_elev(0x21 , pid, saved_regs, 0)) {
        kernel_set_ucred_caps_fast(pid, saved_caps);
        pt_detach(pid);
        return -1;
    }

    long loaded = proc_load_elf_inject((uint32_t)pid, (char *)elf_buf,
                                       (const char *)thread_name);
    if (loaded <= 0) {
        kernel_set_ucred_caps_fast(pid, saved_caps);
        pt_detach(pid);
        return -1;
    }
    *(uint64_t *)(saved_regs + SPCRF_R_RIP) = (uint64_t)loaded;
    *(uint64_t *)(saved_regs + SPCRF_R_RDI) = proc_call_remote_sce(pid);

    kernel_set_ucred_caps_fast(pid, saved_caps);

    if (*(uint64_t *)(saved_regs + SPCRF_R_RDI) == 0) {
        pt_detach(pid);
        return -1;
    }

    int set_rc = (int)ptrace_elev(0x22 , pid, saved_regs, 0);
    int det_rc = pt_detach(pid);
    return (set_rc != 0 ? -1 : 0) | det_rc;
}

long sys_proc_elf(unsigned long pid, unsigned long elf, unsigned long length)
{
    return sys_proc_call_remote_func((int)pid, (void *)elf, length, NULL);
}
