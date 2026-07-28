// SPDX-License-Identifier: GPL-3.0-only


#include "protocol.h"
#include "proc.h"
#include "kern_rw_fast.h"
#include "write_policy.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ps5/klog.h>

#define PTW_PROC_VMSPACE_OFF  0x200ULL
#define PTW_PMAP_OFF_KNOWN    0x300ULL          /* pm_pml4 within vmspace (FW 4.51) */
#define PTW_VMSPACE_SCAN_END  0x400ULL

#define PTW_PTE_PRESENT  0x1ULL
#define PTW_PTE_RW       0x2ULL
#define PTW_PTE_PS       0x80ULL
#define PTW_PTE_NX       0x8000000000000000ULL
#define PTW_PHYS_MASK    0x000FFFFFFFFFF000ULL
#define PTW_PHYS_BOUND   0x1000000000ULL
#define PTW_CANON_KERNEL 0x1FFFFULL

#define PTW_USER_PML4_LIMIT  256
#define PTW_MAX_ENTRIES      16384

static volatile uint64_t g_ptw_gt = 0x5E7C0DE5E7C0DE71ULL;

static int      g_ptw_state    = 0;
static uint64_t g_ptw_dmap     = 0;
static uint64_t g_ptw_pmap_off = 0;

static uint64_t ptw_vtophys(uint64_t dmap, uint64_t cr3, uint64_t va) {
    uint64_t table = cr3 & PTW_PHYS_MASK;
    for (int level = 0; level < 4; level++) {
        if (table >= PTW_PHYS_BOUND) return 0;
        int      shift = 39 - level * 9;
        uint64_t idx   = (va >> shift) & 0x1FF;
        uint64_t e     = 0;
        if (kernel_copyout_fast((intptr_t)(dmap + table + idx * 8), &e, 8) != 0)
            return 0;
        if (!(e & PTW_PTE_PRESENT)) return 0;
        if (level == 3)
            return (e & PTW_PHYS_MASK) | (va & 0xFFF);
        if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) {
            uint64_t pgmask = (level == 1) ? ((1ULL << 30) - 1) : ((1ULL << 21) - 1);
            return ((e & PTW_PHYS_MASK) & ~pgmask) | (va & pgmask);
        }
        table = e & PTW_PHYS_MASK;
    }
    return 0;
}

static int ptw_walk_leaf(uint64_t dmap, uint64_t cr3, uint64_t va,
                         uint64_t *out_e, int *out_level) {
    uint64_t table = cr3 & PTW_PHYS_MASK;
    for (int level = 0; level < 4; level++) {
        if (table >= PTW_PHYS_BOUND) { *out_e = 0; *out_level = level; return 1; }
        int      shift = 39 - level * 9;
        uint64_t idx   = (va >> shift) & 0x1FF;
        uint64_t e     = 0;
        if (kernel_copyout_fast((intptr_t)(dmap + table + idx * 8), &e, 8) != 0) {
            *out_e = 0; *out_level = level; return 1;
        }
        if (!(e & PTW_PTE_PRESENT)) { *out_e = e; *out_level = level; return 1; }
        if (level == 3) { *out_e = e; *out_level = 3; return 0; }
        if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) {
            *out_e = e; *out_level = level; return 0;
        }
        table = e & PTW_PHYS_MASK;
    }
    *out_e = 0; *out_level = -1;
    return 1;
}

static uint64_t ptw_try_offset(uint64_t vmspace, uint64_t off,
                               uint64_t gt_va, uint64_t gt_val) {
    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + off), pair, sizeof(pair)) != 0)
        return 0;

    uint64_t pml4_va = pair[0];
    uint64_t cr3     = pair[1];

    if ((pml4_va >> 47) != PTW_CANON_KERNEL) return 0;
    if (pml4_va & 0xFFF)                     return 0;
    if (cr3 == 0 || (cr3 & 0xFFF))           return 0;
    if (cr3 >= PTW_PHYS_BOUND)               return 0;

    uint64_t dmap = pml4_va - cr3;
    if (dmap & 0xFFFFFFFFULL)                return 0;
    if ((dmap >> 47) != PTW_CANON_KERNEL)    return 0;

    uint64_t phys = ptw_vtophys(dmap, cr3, gt_va);
    if (phys == 0) return 0;

    uint64_t probe = 0;
    if (kernel_copyout_fast((intptr_t)(dmap + phys), &probe, 8) != 0) return 0;
    if (probe != gt_val) return 0;

    return dmap;
}

static int ptw_discover(void) {
    if (g_ptw_state != 0) return g_ptw_state;

    int result = -1;
    intptr_t kproc = kernel_get_proc_fast((pid_t)getpid());
    if (kproc) {
        uint64_t vmspace = 0;
        if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                                &vmspace, 8) == 0 && vmspace) {
            uint64_t gt_va  = (uint64_t)(uintptr_t)&g_ptw_gt;
            uint64_t gt_val = g_ptw_gt;

            uint64_t found_off = PTW_PMAP_OFF_KNOWN;
            uint64_t dmap = ptw_try_offset(vmspace, found_off, gt_va, gt_val);
            if (!dmap) {
                for (uint64_t off = 0x100; off + 16 <= PTW_VMSPACE_SCAN_END; off += 8) {
                    if (off == PTW_PMAP_OFF_KNOWN) continue;
                    dmap = ptw_try_offset(vmspace, off, gt_va, gt_val);
                    if (dmap) { found_off = off; break; }
                }
            }
            if (dmap) {
                g_ptw_dmap     = dmap;
                g_ptw_pmap_off = found_off;
                result = 1;
            }
        }
    }

    g_ptw_state = result;
    klog_printf("[ptw] discover %s dmap=0x%llx pmap_off=0x%llx\n",
                result == 1 ? "OK" : "FAIL",
                (unsigned long long)g_ptw_dmap,
                (unsigned long long)g_ptw_pmap_off);
    return result;
}

struct ptw_coal {
    struct proc_vm_map_entry *ents;
    int      n;
    int      have;
    uint64_t cur_start;
    uint64_t cur_end;
    uint16_t cur_prot;
};

static uint16_t ptw_pte_prot(uint64_t pte) {
    uint16_t prot = 1;
    if (pte & PTW_PTE_RW)    prot |= 2;
    if (!(pte & PTW_PTE_NX)) prot |= 4;
    return prot;
}

static void ptw_coal_flush(struct ptw_coal *c) {
    if (!c->have || c->n >= PTW_MAX_ENTRIES) return;
    struct proc_vm_map_entry *o = &c->ents[c->n];
    memset(o, 0, sizeof(*o));
    o->start  = c->cur_start;
    o->end    = c->cur_end;
    o->offset = 0;
    o->prot   = c->cur_prot;
    memcpy(o->name, "(aux)", 5);
    c->n++;
}

static void ptw_coal_emit(struct ptw_coal *c,
                          uint64_t start, uint64_t end, uint64_t pte) {
    uint16_t prot = ptw_pte_prot(pte);
    if (c->have && start == c->cur_end && prot == c->cur_prot) {
        c->cur_end = end;
        return;
    }
    ptw_coal_flush(c);
    c->have      = 1;
    c->cur_start = start;
    c->cur_end   = end;
    c->cur_prot  = prot;
}

static int ptw_enumerate(uint64_t cr3,
                         struct proc_vm_map_entry **out, int *out_count) {
    uint64_t *pml4 = (uint64_t *)malloc(4096);
    uint64_t *pdpt = (uint64_t *)malloc(4096);
    uint64_t *pd   = (uint64_t *)malloc(4096);
    uint64_t *pt   = (uint64_t *)malloc(4096);
    struct ptw_coal c;
    memset(&c, 0, sizeof(c));
    c.ents = (struct proc_vm_map_entry *)
             malloc((size_t)PTW_MAX_ENTRIES * sizeof(struct proc_vm_map_entry));

    if (!pml4 || !pdpt || !pd || !pt || !c.ents) {
        free(pml4); free(pdpt); free(pd); free(pt); free(c.ents);
        return 1;
    }

    uint64_t pml4_phys = cr3 & PTW_PHYS_MASK;
    if (pml4_phys >= PTW_PHYS_BOUND ||
        kernel_copyout_fast((intptr_t)(g_ptw_dmap + pml4_phys), pml4, 4096) != 0) {
        free(pml4); free(pdpt); free(pd); free(pt); free(c.ents);
        return 1;
    }

    for (int i = 0; i < PTW_USER_PML4_LIMIT && c.n < PTW_MAX_ENTRIES; i++) {
        uint64_t e4 = pml4[i];
        if (!(e4 & PTW_PTE_PRESENT)) continue;
        uint64_t p3 = e4 & PTW_PHYS_MASK;
        if (p3 >= PTW_PHYS_BOUND) continue;
        if (kernel_copyout_fast((intptr_t)(g_ptw_dmap + p3), pdpt, 4096) != 0) continue;

        for (int j = 0; j < 512 && c.n < PTW_MAX_ENTRIES; j++) {
            uint64_t e3  = pdpt[j];
            if (!(e3 & PTW_PTE_PRESENT)) continue;
            uint64_t va3 = ((uint64_t)i << 39) | ((uint64_t)j << 30);
            if (e3 & PTW_PTE_PS) {
                ptw_coal_emit(&c, va3, va3 + (1ULL << 30), e3);
                continue;
            }
            uint64_t p2 = e3 & PTW_PHYS_MASK;
            if (p2 >= PTW_PHYS_BOUND) continue;
            if (kernel_copyout_fast((intptr_t)(g_ptw_dmap + p2), pd, 4096) != 0) continue;

            for (int k = 0; k < 512 && c.n < PTW_MAX_ENTRIES; k++) {
                uint64_t e2  = pd[k];
                if (!(e2 & PTW_PTE_PRESENT)) continue;
                uint64_t va2 = va3 | ((uint64_t)k << 21);
                if (e2 & PTW_PTE_PS) {
                    ptw_coal_emit(&c, va2, va2 + (1ULL << 21), e2);
                    continue;
                }
                uint64_t p1 = e2 & PTW_PHYS_MASK;
                if (p1 >= PTW_PHYS_BOUND) continue;
                if (kernel_copyout_fast((intptr_t)(g_ptw_dmap + p1), pt, 4096) != 0) continue;

                for (int m = 0; m < 512 && c.n < PTW_MAX_ENTRIES; m++) {
                    uint64_t e1  = pt[m];
                    if (!(e1 & PTW_PTE_PRESENT)) continue;
                    uint64_t va1 = va2 | ((uint64_t)m << 12);
                    ptw_coal_emit(&c, va1, va1 + 0x1000, e1);
                }
            }
        }
    }
    ptw_coal_flush(&c);

    free(pml4); free(pdpt); free(pd); free(pt);

    if (c.n == 0) { free(c.ents); return 1; }
    *out       = c.ents;
    *out_count = c.n;
    return 0;
}

static int ptw_merge(struct proc_vm_map_entry *v, int v_count,
                     struct proc_vm_map_entry *e, int e_count,
                     struct proc_vm_map_entry **out_buf, int *out_count) {
    int max_out = v_count + e_count;
    if (max_out <= 0) return 1;

    struct proc_vm_map_entry *o = (struct proc_vm_map_entry *)
        malloc((size_t)max_out * sizeof(struct proc_vm_map_entry));
    if (!o) return 1;

    int iv = 0, ie = 0, io = 0;
    while (iv < v_count && ie < e_count) {
        if (v[iv].start == e[ie].start) {
            o[io++] = v[iv++];
            ie++;
        } else if (v[iv].start < e[ie].start) {
            o[io++] = v[iv++];
        } else {
            o[io++] = e[ie++];
        }
    }
    while (iv < v_count) o[io++] = v[iv++];
    while (ie < e_count) o[io++] = e[ie++];

    *out_buf   = o;
    *out_count = io;
    return 0;
}

#define AUXC_MAX 4096
static struct { uint64_t start, end; } g_auxc[AUXC_MAX];
static int      g_auxc_n   = 0;
static uint32_t g_auxc_pid = 0;

static void auxc_rebuild(uint32_t pid, struct proc_vm_map_entry *m, int n) {
    int k = 0;
    for (int i = 0; i < n && k < AUXC_MAX; i++) {
        const char *nm = m[i].name;
        if (nm[0]=='(' && nm[1]=='a' && nm[2]=='u' && nm[3]=='x' &&
            nm[4]==')' && nm[5]=='\0' && m[i].end > m[i].start) {
            g_auxc[k].start = m[i].start;
            g_auxc[k].end   = m[i].end;
            k++;
        }
    }
    g_auxc_n   = k;
    g_auxc_pid = pid;
}

int proc_aux_range_contains(uint32_t pid, uint64_t addr, uint64_t len) {
    if (pid != g_auxc_pid || g_auxc_n == 0 || len == 0) return 0;
    uint64_t end = addr + len;
    if (end < addr) return 0;
    for (int i = 0; i < g_auxc_n; i++) {
        if (addr >= g_auxc[i].start && end <= g_auxc[i].end) return 1;
    }
    return 0;
}

int proc_ptwalk_augment(uint32_t pid,
                        struct proc_vm_map_entry *v, int v_count,
                        struct proc_vm_map_entry **out_buf, int *out_count) {
    if (out_buf)   *out_buf   = NULL;
    if (out_count) *out_count = 0;
    if ((int32_t)pid <= 0 || !v || v_count <= 0) return 1;

    if (ptw_discover() != 1) return 1;

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return 1;

    uint64_t vmspace = 0;
    if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                            &vmspace, 8) != 0 || !vmspace)
        return 1;

    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + g_ptw_pmap_off),
                            pair, sizeof(pair)) != 0)
        return 1;

    uint64_t cr3 = pair[1];
    if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND) return 1;

    if (pair[0] - cr3 != g_ptw_dmap) {
        klog_printf("[ptw] pid=%u dmap mismatch\n", pid);
        return 1;
    }

    struct proc_vm_map_entry *e = NULL;
    int e_count = 0;
    if (ptw_enumerate(cr3, &e, &e_count) != 0 || e_count == 0) {
        klog_printf("[ptw] pid=%u enumerate failed\n", pid);
        if (e) free(e);
        return 1;
    }

    int rc = ptw_merge(v, v_count, e, e_count, out_buf, out_count);
    if (rc == 0 && out_buf && *out_buf && out_count)
        auxc_rebuild(pid, *out_buf, *out_count);
    klog_printf("[ptw] pid=%u V=%d E=%d merged=%d rc=%d aux_cached=%d\n",
                pid, v_count, e_count, out_count ? *out_count : 0, rc, g_auxc_n);
    free(e);
    return rc;
}

static int ptw_verify_phys(uint32_t pid, uint64_t va, uint64_t phys,
                           const uint8_t *expected, uint64_t len,
                           int diagnostic) {
    uint8_t actual[0x1000];
    uint64_t done = 0;
    while (done < len) {
        uint64_t n = len - done;
        if (n > sizeof(actual)) n = sizeof(actual);
        if (kernel_copyout_fast((intptr_t)(g_ptw_dmap + phys + done),
                                actual, (size_t)n) != 0) {
            klog_printf("[write:dmap] pid=%u va=0x%llx len=%llu "
                        "verify-read failed at +0x%llx\n",
                        pid, (unsigned long long)va,
                        (unsigned long long)len,
                        (unsigned long long)done);
            return PROC_PTW_WRITE_VERIFY_FAILED;
        }
        if (memcmp(actual, expected + done, (size_t)n) != 0) {
            uint64_t mismatch = 0;
            while (mismatch < n
                   && actual[mismatch] == expected[done + mismatch])
                mismatch++;
            klog_printf("[write:dmap] pid=%u verify mismatch va=0x%llx "
                        "expected=%02x actual=%02x\n",
                        pid, (unsigned long long)(va + done + mismatch),
                        expected[done + mismatch], actual[mismatch]);
            return PROC_PTW_WRITE_VERIFY_FAILED;
        }
        done += n;
    }
    if (diagnostic) {
        klog_printf("[write:dmap] pid=%u va=0x%llx len=%llu verify=OK\n",
                    pid, (unsigned long long)va,
                    (unsigned long long)len);
    }
    return PROC_PTW_WRITE_OK;
}

int proc_ptwalk_write(uint32_t pid, uint64_t va, uint64_t len, const void *src) {
    if ((int32_t)pid <= 0 || !src || len == 0 || va + len < va)
        return PROC_PTW_WRITE_RESOLVE_FAILED;
    if (ptw_discover() != 1) return PROC_PTW_WRITE_RESOLVE_FAILED;

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return PROC_PTW_WRITE_RESOLVE_FAILED;

    uint64_t vmspace = 0;
    if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                            &vmspace, 8) != 0 || !vmspace)
        return PROC_PTW_WRITE_RESOLVE_FAILED;

    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + g_ptw_pmap_off),
                            pair, sizeof(pair)) != 0)
        return PROC_PTW_WRITE_RESOLVE_FAILED;

    uint64_t cr3 = pair[1];
    if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND)
        return PROC_PTW_WRITE_RESOLVE_FAILED;
    if (pair[0] - cr3 != g_ptw_dmap)
        return PROC_PTW_WRITE_RESOLVE_FAILED;

    const uint8_t *in   = (const uint8_t *)src;
    uint64_t       done = 0;
    while (done < len) {
        uint64_t cur_va = va + done;
        uint64_t e   = 0;
        int      lvl = -1;
        if (ptw_walk_leaf(g_ptw_dmap, cr3, cur_va, &e, &lvl) != 0)
            return PROC_PTW_WRITE_RESOLVE_FAILED;

        uint64_t page_size;
        if      (lvl == 3) page_size = 0x1000ULL;
        else if (lvl == 2) page_size = 0x200000ULL;
        else if (lvl == 1) page_size = 0x40000000ULL;
        else return PROC_PTW_WRITE_RESOLVE_FAILED;

        uint64_t page_mask   = page_size - 1;
        uint64_t off_in_page = cur_va & page_mask;
        uint64_t phys        = ((e & PTW_PHYS_MASK) & ~page_mask) + off_in_page;

        uint64_t n = len - done;
        uint64_t avail = page_size - off_in_page;
        if (n > avail) n = avail;

        if (phys >= PTW_PHYS_BOUND || phys + n < phys
            || phys + n > PTW_PHYS_BOUND)
            return PROC_PTW_WRITE_RESOLVE_FAILED;

        int diagnostic = ps5debug_write_diagnostics_enabled();
        if (diagnostic) {
            klog_printf("[write:dmap] pid=%u va=0x%llx len=%llu "
                        "level=%d phys=0x%llx pte=0x%llx\n",
                        pid, (unsigned long long)cur_va,
                        (unsigned long long)n, lvl,
                        (unsigned long long)phys,
                        (unsigned long long)e);
        }
        if (kernel_copyin_fast(in + done,
                               (intptr_t)(g_ptw_dmap + phys), n) != 0) {
            klog_printf("[write:dmap] pid=%u va=0x%llx len=%llu "
                        "copy failed level=%d phys=0x%llx pte=0x%llx\n",
                        pid, (unsigned long long)cur_va,
                        (unsigned long long)n, lvl,
                        (unsigned long long)phys,
                        (unsigned long long)e);
            return PROC_PTW_WRITE_COPY_FAILED;
        }
        int verify_rc = ptw_verify_phys(pid, cur_va, phys, in + done,
                                        n, diagnostic);
        if (verify_rc != PROC_PTW_WRITE_OK) return verify_rc;
        done += n;
    }
    return PROC_PTW_WRITE_OK;
}

int proc_ptwalk_read(uint32_t pid, uint64_t va, uint64_t len, void *dst) {
    if ((int32_t)pid <= 0 || !dst || len == 0) return 1;
    if (ptw_discover() != 1) return 1;

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return 1;

    uint64_t vmspace = 0;
    if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                            &vmspace, 8) != 0 || !vmspace)
        return 1;

    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + g_ptw_pmap_off),
                            pair, sizeof(pair)) != 0)
        return 1;

    uint64_t cr3 = pair[1];
    if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND) return 1;
    if (pair[0] - cr3 != g_ptw_dmap) return 1;

    uint8_t *out  = (uint8_t *)dst;
    uint64_t done = 0;
    while (done < len) {
        uint64_t cur_va = va + done;
        uint64_t e = 0;
        int      lvl = -1;
        if (ptw_walk_leaf(g_ptw_dmap, cr3, cur_va, &e, &lvl) != 0) return 1;

        uint64_t page_size;
        if      (lvl == 3) page_size = 0x1000ULL;
        else if (lvl == 2) page_size = 0x200000ULL;
        else if (lvl == 1) page_size = 0x40000000ULL;
        else return 1;

        uint64_t page_mask   = page_size - 1;
        uint64_t off_in_page = cur_va & page_mask;
        uint64_t phys        = ((e & PTW_PHYS_MASK) & ~page_mask) + off_in_page;

        uint64_t n = len - done;
        uint64_t avail = page_size - off_in_page;
        if (n > avail) n = avail;

        if (phys >= PTW_PHYS_BOUND || phys + n > PTW_PHYS_BOUND) return 1;
        if (kernel_copyout_fast((intptr_t)(g_ptw_dmap + phys), out + done, n) != 0)
            return 1;
        done += n;
    }
    return 0;
}

// --- benchmark/diagnostic accessors (read-only) ---

uint64_t proc_ptwalk_dmap_base(void) { return g_ptw_dmap; }

// Return the kernel (DMAP) address where the 4K leaf PTE for `va` LIVES, plus
// its current value. Mirrors the proven ptw_walk_leaf exactly. For aliasing
// (caller overwrites the leaf PTE). Return: 0 = 4K leaf addr returned (value may
// be not-present, which is expected for an untouched window page); 2 = an upper
// level was not present (PT not allocated - touch a sibling first); 3 = huge
// page (no 4K leaf); 1 = error.
int proc_ptwalk_leaf_addr(uint32_t pid, uint64_t va, uint64_t *out_pte_kaddr,
                          uint64_t *out_pte_val, int *out_level) {
    if ((int32_t)pid <= 0) return 1;
    if (ptw_discover() != 1) return 1;

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return 1;

    uint64_t vmspace = 0;
    if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                            &vmspace, 8) != 0 || !vmspace)
        return 1;

    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + g_ptw_pmap_off),
                            pair, sizeof(pair)) != 0)
        return 1;

    uint64_t cr3 = pair[1];
    if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND) return 1;
    if (pair[0] - cr3 != g_ptw_dmap) return 1;

    uint64_t table = cr3 & PTW_PHYS_MASK;
    for (int level = 0; level < 4; level++) {
        if (table >= PTW_PHYS_BOUND) return 1;
        int      shift     = 39 - level * 9;
        uint64_t idx       = (va >> shift) & 0x1FF;
        uint64_t ent_kaddr = g_ptw_dmap + table + idx * 8;
        uint64_t e = 0;
        if (kernel_copyout_fast((intptr_t)ent_kaddr, &e, 8) != 0) return 1;

        if (level == 3) {
            if (out_pte_kaddr) *out_pte_kaddr = ent_kaddr;
            if (out_pte_val)   *out_pte_val   = e;
            if (out_level)     *out_level     = 3;
            return 0;
        }
        if (!(e & PTW_PTE_PRESENT)) return 2;
        if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) return 3;
        table = e & PTW_PHYS_MASK;
    }
    return 1;
}

// Resolve one VA to its leaf phys + page size (4K/2M/1G). For benchmarking the
// DMAP read path: lets the caller find a huge-page-backed VA and copyout from
// g_ptw_dmap+phys directly.
int proc_ptwalk_probe(uint32_t pid, uint64_t va, uint64_t *out_phys,
                      int *out_level, uint64_t *out_pagesize, uint64_t *out_pte) {
    if ((int32_t)pid <= 0) return 1;
    if (ptw_discover() != 1) return 1;

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return 1;

    uint64_t vmspace = 0;
    if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                            &vmspace, 8) != 0 || !vmspace)
        return 1;

    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + g_ptw_pmap_off),
                            pair, sizeof(pair)) != 0)
        return 1;

    uint64_t cr3 = pair[1];
    if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND) return 1;
    if (pair[0] - cr3 != g_ptw_dmap) return 1;

    uint64_t e = 0;
    int      lvl = -1;
    if (ptw_walk_leaf(g_ptw_dmap, cr3, va, &e, &lvl) != 0) return 1;
    if (!(e & PTW_PTE_PRESENT)) return 1;

    uint64_t page_size = (lvl == 3) ? 0x1000ULL
                       : (lvl == 2) ? 0x200000ULL
                       : (lvl == 1) ? 0x40000000ULL : 0;
    if (!page_size) return 1;

    uint64_t page_mask = page_size - 1;
    if (out_phys)     *out_phys     = ((e & PTW_PHYS_MASK) & ~page_mask) + (va & page_mask);
    if (out_level)    *out_level    = lvl;
    if (out_pagesize) *out_pagesize = page_size;
    if (out_pte)      *out_pte      = e;
    return 0;
}

// Unified per-2MB-span resolve for the aliasing read engine (read-only). One PD-walk
// (PML4->PDPT->PD, ~3 kernel reads) for a 2MB-aligned `span2m`, then branch on the PS
// bit: a 1GB (PDPT PS) or 2MB (PD PS) superpage returns is_huge + the phys of span2m's
// first byte (the 2MB span is phys-contiguous inside any superpage) + the huge PTE; a
// non-PS PD entry returns is_huge=0 + the DMAP kaddr of the 512-entry leaf PT page (the
// caller bulk-reads it once and indexes per 4K page). ~256-512x cheaper than per-4K-page
// proc_ptwalk_probe on 4K-paged targets; identical on huge. Mirrors ptw_walk_leaf's reads.
int proc_ptwalk_span_resolve(uint32_t pid, uint64_t span2m, int *out_huge,
                             uint64_t *out_phys_base, uint64_t *out_leaf_pt_kaddr,
                             uint64_t *out_pte) {
    if ((int32_t)pid <= 0) return 1;
    if (ptw_discover() != 1) return 1;

    intptr_t kproc = kernel_get_proc_fast((pid_t)pid);
    if (!kproc) return 1;

    uint64_t vmspace = 0;
    if (kernel_copyout_fast((intptr_t)(kproc + PTW_PROC_VMSPACE_OFF),
                            &vmspace, 8) != 0 || !vmspace)
        return 1;

    uint64_t pair[2];
    if (kernel_copyout_fast((intptr_t)(vmspace + g_ptw_pmap_off),
                            pair, sizeof(pair)) != 0)
        return 1;

    uint64_t cr3 = pair[1];
    if (cr3 == 0 || (cr3 & 0xFFF) || cr3 >= PTW_PHYS_BOUND) return 1;
    if (pair[0] - cr3 != g_ptw_dmap) return 1;

    uint64_t table = cr3 & PTW_PHYS_MASK;
    for (int level = 0; level < 3; level++) {               // PML4(0) -> PDPT(1) -> PD(2)
        if (table >= PTW_PHYS_BOUND) return 1;
        int      shift = 39 - level * 9;
        uint64_t idx   = (span2m >> shift) & 0x1FF;
        uint64_t e = 0;
        if (kernel_copyout_fast((intptr_t)(g_ptw_dmap + table + idx * 8), &e, 8) != 0)
            return 1;
        if (!(e & PTW_PTE_PRESENT)) return 1;
        if ((level == 1 || level == 2) && (e & PTW_PTE_PS)) { // 1GB or 2MB superpage
            uint64_t pgsz = (level == 1) ? (1ULL << 30) : (1ULL << 21);
            uint64_t base = (e & PTW_PHYS_MASK) & ~(pgsz - 1);
            if (out_huge)          *out_huge          = 1;
            if (out_phys_base)     *out_phys_base     = base + (span2m & (pgsz - 1));
            if (out_pte)           *out_pte           = e;
            if (out_leaf_pt_kaddr) *out_leaf_pt_kaddr = 0;
            return 0;
        }
        table = e & PTW_PHYS_MASK;                          // descend
    }
    // PD entry was a non-PS pointer -> `table` is now the leaf PT page's phys.
    if (table >= PTW_PHYS_BOUND) return 1;
    if (out_huge)          *out_huge          = 0;
    if (out_leaf_pt_kaddr) *out_leaf_pt_kaddr = g_ptw_dmap + table;
    if (out_phys_base)     *out_phys_base     = 0;
    if (out_pte)           *out_pte           = 0;
    return 0;
}
