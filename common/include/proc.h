// SPDX-License-Identifier: GPL-3.0-only

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct cmd_packet;

int proc_handle(int fd, struct cmd_packet *packet, unsigned char client_idx);

int proc_list_handle(int fd, struct cmd_packet *packet);
int proc_read_handle(int fd, struct cmd_packet *packet);
int proc_read_stack_handle(int fd, struct cmd_packet *packet);
int proc_write_handle(int fd, struct cmd_packet *packet);
int proc_write_multi_handle(int fd, struct cmd_packet *packet);
int proc_maps_handle(int fd, struct cmd_packet *packet);
int proc_info_handle(int fd, struct cmd_packet *packet);
int proc_protect_handle(int fd, struct cmd_packet *packet);
int proc_unknown_d_handle(int fd, struct cmd_packet *packet);

int proc_install_handle(int fd, struct cmd_packet *packet);
int proc_call_handle(int fd, struct cmd_packet *packet);
int proc_elf_handle(int fd, struct cmd_packet *packet);
int proc_elf_rpc_handle(int fd, struct cmd_packet *packet);

long proc_load_elf_inject(uint32_t pid, char *elf_buf, const char *thread_name);
long sys_proc_elf(unsigned long pid, unsigned long elf, unsigned long length);

int ptrace_io_write_d(int pid, void *src_local, void *dst_target, uint64_t len);
int proc_alloc_handle(int fd, struct cmd_packet *packet);
int proc_free_handle(int fd, struct cmd_packet *packet);
int proc_alloc_hinted_handle(int fd, struct cmd_packet *packet);

int proc_disasm_region_handle(int fd, struct cmd_packet *packet);
int proc_extract_code_xrefs_handle(int fd, struct cmd_packet *packet);
int proc_find_xrefs_to_handle(int fd, struct cmd_packet *packet);

struct sys_proc_call_args;
int proc_remote_alloc(uint32_t pid, uint64_t *out_addr,
                       uint64_t length, uint64_t hint);
int proc_remote_free (uint32_t pid, uint64_t addr, uint64_t length);
int proc_remote_call (int pid, struct sys_proc_call_args *args);

struct elev_state {
    unsigned long saved_authid;
    uint8_t       saved_caps[16];
    int           valid;
};
long ptrace_raw (int op, int pid, void *addr, int data);
long ptrace_elev(int op, int pid, void *addr, int data);
int  elev_save_and_set(struct elev_state *st);
void elev_restore     (struct elev_state *st);
int  proc_arena_set(int on, char *buf, int bufsz);

long sys_proc_rw_w0(uint64_t pid, uint64_t address, uint64_t length,
                    void *data, uint64_t arg5);
long sys_proc_rw_w1(uint64_t pid, uint64_t address, uint64_t length,
                    void *data, uint64_t arg5);

int proc_scan_handle(int fd, struct cmd_packet *packet);
int proc_scan_aob_handle(int fd, struct cmd_packet *packet);
int proc_scan_aob_multi_handle(int fd, struct cmd_packet *packet);
int proc_scan_start_handle(int fd, struct cmd_packet *packet);
int proc_scan_count_handle(int fd, struct cmd_packet *packet);
int proc_scan_get_handle(int fd, struct cmd_packet *packet);
int proc_turboscan_caps_handle(int fd, struct cmd_packet *packet);
int proc_turboscan_config_handle(int fd, struct cmd_packet *packet);
int proc_turboscan_start_handle(int fd, struct cmd_packet *packet, unsigned char client_idx);
int proc_turboscan_count_handle(int fd, struct cmd_packet *packet, unsigned char client_idx);
int proc_turboscan_get_handle(int fd, struct cmd_packet *packet, unsigned char client_idx);
int proc_turboscan_end_handle(int fd, struct cmd_packet *packet, unsigned char client_idx);
int proc_turboscan_regions_handle(int fd, struct cmd_packet *packet);
int proc_turboscan_cancel_handle(int fd, struct cmd_packet *packet);   /* 0xBDAACC17 (from a 2nd connection) */

void turboscan_session_free_idx(unsigned char client_idx);

void turboscan_alias_free_idx(unsigned char client_idx);

void turboscan_startup_cleanup(void);
int proc_auth_handle(int fd, struct cmd_packet *packet);
int proc_assemble_handle(int fd, struct cmd_packet *packet);

bool proc_scan_legacy_compareValues(unsigned char cmpType, unsigned char valType,
                                    uint64_t valueLength,
                                    const void *scanValue,
                                    const void *memValue,
                                    const void *extraValue);

bool proc_scan_compareValues(unsigned char cmpType, unsigned char valType,
                             uint64_t valueLength,
                             const void *scanValue,
                             const void *memValue,
                             const void *prevValue,
                             const void *mask);

bool aob_match(uint64_t pattern_length,
               const uint8_t *pattern,
               const uint8_t *memory,
               uint64_t unused,
               const uint8_t *mask);

bool fuzzy_double_compare(double scanV, double memV, double tolerance);
bool fuzzy_float_compare(float  scanV, float  memV, float  tolerance);

uint64_t proc_scan_getSizeOfValueType(unsigned char valType);

uint32_t auth_lfsr_next(void);
void     auth_lfsr_set_state(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
void     auth_keystream_fill(uint8_t *out, uint64_t length);
void     proc_auth_xor_keystream(const uint8_t *in, uint8_t *out, uint16_t length);

extern const uint8_t g_cmptype_needs_value   [16];
extern const uint8_t g_cmptype_needs_extra   [16];
extern const uint8_t g_cmptype_needs_previous[16];

extern uint32_t g_proc_auth_state;

int sys_proc_vm_map(uint32_t pid, void **out_maps, int *out_count);

struct proc_vm_map_entry;
int proc_ptwalk_augment(uint32_t pid,
                        struct proc_vm_map_entry *v, int v_count,
                        struct proc_vm_map_entry **out_buf, int *out_count);

int proc_ptwalk_read(uint32_t pid, uint64_t va, uint64_t len, void *dst);

uint64_t proc_ptwalk_dmap_base(void);
int proc_ptwalk_probe(uint32_t pid, uint64_t va, uint64_t *out_phys,
                      int *out_level, uint64_t *out_pagesize, uint64_t *out_pte);
int proc_ptwalk_leaf_addr(uint32_t pid, uint64_t va, uint64_t *out_pte_kaddr,
                          uint64_t *out_pte_val, int *out_level);

int proc_ptwalk_span_resolve(uint32_t pid, uint64_t span2m, int *out_huge,
                             uint64_t *out_phys_base, uint64_t *out_leaf_pt_kaddr,
                             uint64_t *out_pte);

int proc_ptwalk_write(uint32_t pid, uint64_t va, uint64_t len, const void *src);

int proc_aux_range_contains(uint32_t pid, uint64_t addr, uint64_t len);

void proc_read_mem(uint32_t pid, uint64_t addr, uint64_t len, void *buf);
void proc_write_mem(uint32_t pid, uint64_t addr, uint64_t len, const void *buf);
