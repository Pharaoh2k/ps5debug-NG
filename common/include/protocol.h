// SPDX-License-Identifier: GPL-3.0-only

#ifndef _PS5DEBUG_PROTOCOL_H
#define _PS5DEBUG_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define CMD_SUCCESS         0x40000000u
#define CMD_DATA_NULL       0xF0000003u
#define CMD_ERROR           0xF0000002u
#define CMD_ALREADY_DEBUG   0xF0000008u

#define CMD_VERSION         0xBD000001u
#define CMD_FW_VERSION      0xBD000500u
#define CMD_BRANDING        0xBD000501u
#define CMD_PLATFORM_ID     0xBD000502u
#define CMD_PROC_NOP        0xBDAACC06u

/* TURBOSCAN family (additive; legacy 0xBDAA0009 + async 0xBDAACC01/02/03 unchanged).
 * Opcodes 0xBDAACC10..0xBDAACC15 are RAW LITERALS with NO CMD_* macro - the published
 * CMD_* set that some clients enumerate must stay unchanged (see README), so new commands
 * are dispatched by hex literal in the per-namespace switch:
 *   0xBDAACC10 CAPS  0xBDAACC11 START  0xBDAACC12 COUNT
 *   0xBDAACC13 GET   0xBDAACC14 END    0xBDAACC15 CONFIG (RAM threshold + spill dir) */

/* TURBOSCAN engine bits (CAPS response) */
#define TSE_SIMD_COMPARE    0x00000001u
#define TSE_ALIASING        0x00000002u       /* Phase 3; advertised only when built+enabled */
#define TSE_SERVER_RESIDENT 0x00000004u       /* Phase 2b: server-resident survivor sets */
#define TSE_SNAPSHOT        0x00000008u       /* Phase 2c: unknown-value NVMe snapshot scans */
#define TSE_SNAPSHOT_SEGMENTS 0x00000010u     /* server understands a trailing segment list (disjoint regions in one session): snapshot + resident START */
#define TSE_SNAPSHOT_CONFIG   0x00000020u     /* CMD_PROC_TURBOSCAN_CONFIG (RAM threshold + spill dir) supported */
#define TSE_SNAPSHOT_FIRST    0x00000040u     /* TS_SNAPSHOT_KEEP_FIRST + CC13 GET first-scan value (3-value records) supported */
#define TSE_SNAPSHOT_PREVIOUS 0x00000080u     /* TS_SNAPSHOT_KEEP_PREVIOUS: CC13 GET "previous" = prior-scan value (not last-scan) */
#define TSE_PARALLEL_COMPARE  0x00000100u     /* TS_PARALLEL_COMPARE supported (server-side multi-thread for the aliased SIMD exact-match streaming scan) */
#define TSE_RESCAN_ALIASING   0x00000200u     /* TS_RESCAN_ALIASING supported (CC12 rescan reads full-size survivor windows via the aliasing engine) */
#define TSE_FLOAT_POLICY      0x00000400u     /* TS_FLOAT_SIMPLE / TS_FLOAT_EXACT + packed exponent threshold supported */
#define TSE_COMPACT_SIMPLE_SNAPSHOT 0x00000800u /* TS_FLOAT_SIMPLE snapshots store survivor records instead of raw-slot-dense backing */

/* TURBOSCAN START/COUNT flags (per-request; opt-in). Phase 1 honored none. */
#define TS_USE_ALIASING    0x00000001u        /* Phase 3 read engine (client opt-in) */
#define TS_SERVER_RESIDENT 0x00000002u        /* Phase 2b: keep/rescan survivors server-side */
#define TS_SNAPSHOT        0x00000004u        /* Phase 2c: unknown-initial-value snapshot scan */
#define TS_SNAPSHOT_INCLUDE_ZEROS 0x00000008u /* 2c snapshot: seed all-zero slots too; DEFAULT drops them */
#define TS_SNAPSHOT_SEGMENTS 0x00000010u      /* START: cover a trailing segment list of disjoint regions (with TS_SNAPSHOT or TS_SERVER_RESIDENT; see below) */
#define TS_SNAPSHOT_KEEP_FIRST 0x00000020u    /* START+TS_SNAPSHOT: retain an immutable first-scan value store so CC13 GET can return first (3-value records) */
#define TS_SNAPSHOT_KEEP_PREVIOUS 0x00000040u /* START+TS_SNAPSHOT: retain a prior-scan value store so CC13 GET "previous" = value at the previous scan (not the just-matched value) */
#define TS_PARALLEL_COMPARE 0x00000080u       /* START+TS_USE_ALIASING, exact-match streaming: split the scan across worker threads server-side. For SINGLE-connection clients - multi-connection clients should fan out across connections instead (do NOT combine; over-subscribes) */
#define TS_RESCAN_ALIASING  0x00000100u       /* CC12 (client opt-in): read full-size (bridging-dense) survivor windows via the aliasing engine instead of mdbg; tiny scattered windows + any alias failure fall back to mdbg (the floor). ~2-3x on dense/moderate rescans; single-connection clients (the survivor set is per-connection) - do NOT enable on many connections at once (over-subscribes the aliasing setup like TS_PARALLEL_COMPARE) */
#define TS_FLOAT_SIMPLE     0x00000200u       /* float/double: retain only positive zero or values within the packed exponent distance of 1.0 */
#define TS_FLOAT_EXACT      0x00000400u       /* exact-value float/double: numeric IEEE equality instead of the legacy fuzzy comparator */
#define TS_FLOAT_EXPONENT_SHIFT 16u           /* TS_FLOAT_SIMPLE threshold: 7-bit unsigned exponent distance (1..127; 0 => 11) */
#define TS_FLOAT_EXPONENT_MASK  0x007F0000u

#define VALID_CMD(cmd)          (((cmd) >> 24) == 0xBDu)
#define VALID_PROC_CMD(cmd)     ((((cmd) >> 16) & 0xFFu) == 0xAAu)
#define VALID_DEBUG_CMD(cmd)    ((((cmd) >> 16) & 0xFFu) == 0xBBu)
#define VALID_KERN_CMD(cmd)     ((((cmd) >> 16) & 0xFFu) == 0xCCu)
#define VALID_CONSOLE_CMD(cmd)  ((((cmd) >> 16) & 0xFFu) == 0xDDu)

struct cmd_packet {
    uint32_t magic;
    uint32_t cmd;
    uint32_t datalen;
    void    *data;
} __attribute__((packed));

struct cmd_kern_read_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct cmd_kern_write_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct proc_list_entry {
    char     name[32];
    int32_t  pid;
} __attribute__((packed));

struct cmd_proc_alloc_packet {
    uint32_t pid;
    uint32_t length;
} __attribute__((packed));
struct cmd_proc_alloc_response {
    uint64_t address;
} __attribute__((packed));
#define CMD_PROC_ALLOC_PACKET_SIZE 8

struct cmd_proc_alloc_hinted_packet {
    uint32_t pid;
    uint64_t hint;
    uint32_t length;
} __attribute__((packed));

struct cmd_proc_free_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct cmd_proc_install_packet {
    uint32_t pid;
} __attribute__((packed));

struct cmd_proc_unknown_d_packet {
    uint32_t pid;
} __attribute__((packed));

struct cmd_proc_read_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

struct cmd_proc_read_stack_packet {
    uint32_t pid;
    uint64_t rbp;
    uint64_t rsp;
    uint32_t depth;
} __attribute__((packed));
#define CMD_PROC_READ_STACK_PACKET_SIZE 24
#define CMD_PROC_READ_STACK_CODE_OFF   10u
#define CMD_PROC_READ_STACK_CODE_LEN   200u
#define CMD_PROC_READ_STACK_LOCALS_CAP 0x1000u
#define CMD_PROC_READ_STACK_MAX_DEPTH  64u

#define CMD_PROC_ASSEMBLE_HDR_SIZE     12u
struct cmd_proc_assemble_packet {
    uint64_t base_addr;
    uint32_t ks_opt_syntax;
} __attribute__((packed));
struct cmd_proc_assemble_ok {
    uint32_t byte_len;
    uint32_t insn_count;
} __attribute__((packed));
struct cmd_proc_assemble_err {
    uint32_t ks_errno;
    uint32_t msg_len;
} __attribute__((packed));

struct cmd_proc_write_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} __attribute__((packed));

/* Bulk write / freeze batching (opcode 0xBDAACC04). Header body below is
   followed by `count` streamed entries, each { uint64 address; uint32 length;
   <length> bytes }. flags bit 0 asks the server for a per-entry status byte
   array sent just before the trailing CMD_SUCCESS; any nonzero byte is a
   failure code below. Without that flag, any failed entry makes the trailing
   status CMD_ERROR. */
struct cmd_proc_write_multi_packet {
    uint32_t pid;
    uint32_t count;
    uint32_t flags;
} __attribute__((packed));
#define PROC_WRITE_MULTI_F_STATUS   0x1u
#define PROC_WRITE_MULTI_MAX_COUNT  0xFFFFu
#define PROC_WRITE_MULTI_MAX_ENTRY  0x100000u

#define PROC_WRITE_STATUS_OK             0u
#define PROC_WRITE_STATUS_INVALID        1u
#define PROC_WRITE_STATUS_DMAP_FAILED    2u
#define PROC_WRITE_STATUS_VERIFY_FAILED  3u
#define PROC_WRITE_STATUS_MDBG_FAILED    4u

struct cmd_proc_maps_packet {
    uint32_t pid;
} __attribute__((packed));

struct cmd_proc_call_packet {
    uint32_t pid;
    uint64_t rpcstub;
    uint64_t rpc_rip;
    uint64_t rpc_rdi;
    uint64_t rpc_rsi;
    uint64_t rpc_rdx;
    uint64_t rpc_rcx;
    uint64_t rpc_r8;
    uint64_t rpc_r9;
} __attribute__((packed));

struct sys_proc_call_args {
    uint32_t pid;
    uint64_t rpcstub;
    uint64_t rax;
    uint64_t rip;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t r8;
    uint64_t r9;
} __attribute__((packed));

struct cmd_proc_call_response {
    uint32_t pid;
    uint64_t rpc_rax;
} __attribute__((packed));

struct cmd_proc_elf_packet {
    uint32_t pid;
    uint32_t length;
} __attribute__((packed));

struct proc_vm_map_entry {
    char     name[32];
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t prot;
} __attribute__((packed));

struct cmd_proc_scan_start_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t  valueType;
    uint8_t  compareType;
    uint8_t  alignment;
    uint32_t lenData;
} __attribute__((packed));

struct cmd_proc_scan_count_packet {
    uint32_t pid;
    uint64_t base_address;
    uint8_t  valueType;
    uint8_t  compareType;
    uint32_t lenData;
} __attribute__((packed));

/* TURBOSCAN START request: mirrors cmd_proc_scan_start_packet + a flags field.
 * Result wire format is identical to the async START (batched (offset,value)
 * runs, 8-byte 0xFFFF... sentinel) so clients reuse their result parser. */
struct cmd_proc_turboscan_start_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t  valueType;
    uint8_t  compareType;
    uint8_t  alignment;
    uint32_t lenData;
    uint32_t flags;          /* TS_* */
} __attribute__((packed));

/* TURBOSCAN config (CC15): set the snapshot value-store RAM threshold + spill directory
 * (global; affects the next snapshot create). Body = this header + spill_path_len path
 * bytes (no NUL). ram_thresh_mb 0 => reset to the 512MB default; spill_path_len 0 =>
 * reset spill dir to /data. Reply: CMD_SUCCESS. Advertised via TSE_SNAPSHOT_CONFIG.
 * ram_thresh_mb is the amount FULLY COMMITTED to RAM: a store <= it is pure anon RAM;
 * a larger store is HYBRID - the first ram_thresh_mb (whole slots) is cached in anon
 * RAM and only the overflow spills to the file (the kernel page cache may keep extra
 * spill pages warm on top). So raising it commits more RAM up front but a too-large
 * scan no longer goes 100% to disk. */
struct cmd_proc_turboscan_config_packet {
    uint32_t ram_thresh_mb;   /* RAM committed to the value store; overflow spills to a file */
    uint32_t spill_path_len;  /* length of the trailing spill-directory string (<=63) */
} __attribute__((packed));

struct cmd_proc_turboscan_caps_response {
    uint32_t version;        /* turboscan protocol version (1) */
    uint32_t engines;        /* TSE_* bitmask of supported engines */
    uint32_t max_threads;    /* worker threads the compare stage will use */
    uint32_t reserved;
} __attribute__((packed));

/* Region-classify query (opcode 0xBDAACC16, raw literal). Returns every readable
   region of the target with its cache attribute + a measured read throughput, so the
   client can let the user exclude uncached/slow regions (e.g. the GPU/Garlic blob).
   The server does NOT drop anything - exclusion is the client's choice. */
struct cmd_proc_turboscan_regions_packet {
    uint32_t pid;
    uint32_t max;            /* cap on regions returned (0 => server default) */
    uint32_t probe_bytes;    /* bytes probe-read per region to measure MB/s (0 => 64 KiB) */
    uint32_t reserved;
} __attribute__((packed));

struct cmd_proc_turboscan_region_info {
    uint64_t start;
    uint64_t end;
    uint32_t prot;           /* protection bits (low 3: read/write/exec) */
    uint32_t flags;          /* bit0 = leaf PTE PCD=1 (uncached / slow) */
    uint32_t mbps;           /* measured read throughput, whole MB/s */
    uint32_t reserved;
} __attribute__((packed));   /* 32 bytes */

/* TURBOSCAN rescan (COUNT) request: mirrors cmd_proc_scan_count_packet + a flags
 * field (forward-compat for a Phase-3 aliasing rescan). The streaming wire format
 * (per-chunk candidate offsets in, batched (offset,value) runs + 0xFFFF... per-chunk
 * sentinel out, final CMD_SUCCESS) is identical to the async COUNT so clients reuse
 * one parser. Phase 2 echoes `flags` and honors none. */
struct cmd_proc_turboscan_count_packet {
    uint32_t pid;
    uint64_t base_address;
    uint8_t  valueType;
    uint8_t  compareType;
    uint32_t lenData;
    uint32_t flags;          /* TS_* */
} __attribute__((packed));

/* TURBOSCAN server-resident replies/requests (Phase 2b). When a START/COUNT carries
 * TS_SERVER_RESIDENT, the survivor set lives in a per-connection mmap buffer instead
 * of being streamed. START replies this summary (and streams NO result runs) unless
 * resident_stored==0 (overflow / mmap-fail / unsupported) in which case the full
 * (offset,value) result runs follow exactly as the non-resident path.
 *
 * Multi-segment resident (START with TS_SERVER_RESIDENT|TS_SNAPSHOT_SEGMENTS, TS_SNAPSHOT
 * clear): after the 2nd ack the client streams a segment list (u32 segment_count, then
 * segment_count x cmd_proc_turboscan_snap_segment) IDENTICAL to the snapshot sub-protocol;
 * the packet address/length are ignored. The server scans each disjoint segment, appending
 * matches into the one session buffer; survivors are stored as absolute [u64 addr][value]
 * so CC12 narrow / CC13 GET are geometry-independent. On resident_stored==1 the reply is
 * the same 12-byte summary (count = total across segments). On resident_stored==0 (overflow
 * / malformed segment_count / OOM) there is NO transparent stream fallback (a u32 offset
 * cannot carry >4GB-scattered absolute addresses): the framing stays byte-identical - the
 * summary{0,0} is followed by an EMPTY run stream (an immediate 0xFFFF.. sentinel) and the
 * final CMD_SUCCESS - and the client falls back to its own per-section streaming. */
struct cmd_proc_turboscan_resident_summary {
    uint32_t resident_stored;   /* 1 = kept server-side; 0 = runs streamed next */
    uint64_t count;             /* survivors stored (valid iff resident_stored==1) */
} __attribute__((packed));

/* TURBOSCAN snapshot (CC11 + TS_SNAPSHOT) reply, after the two leading CMD_SUCCESS:
 *   plan { slot_count, total_bytes }   -- up front so the UI can show progress
 *   progress: repeated uint64 bytes_done records, terminated by an 8-byte 0xFFFF..
 *   summary { snapshot_ok, survivor_count }  -- snapshot_ok=0 => ENOSPC/fail, client
 *   falls back to its client-driven unknown-value path
 *   final CMD_SUCCESS.
 * Subsequent narrowing uses CC12 + TS_SERVER_RESIDENT (rescans the snapshot in place,
 * since-last-scan), and CC13 GET fetches survivors. */
/* TURBOSCAN multi-segment snapshot (CC11 + TS_SNAPSHOT + TS_SNAPSHOT_SEGMENTS).
 * After the two leading CMD_SUCCESS acks and the value/mask trailing data, the client
 * streams: uint32 segment_count, then segment_count x this struct. The snapshot then
 * covers exactly those (disjoint) regions as one resident session - the slot space is
 * the concatenation of the segments, so unmapped gaps between them are never read and
 * storage scales with selected bytes, not with the bounding span. The packet's
 * `address`/`length` are ignored in this mode. survivor addresses are absolute, so
 * CC12 narrow / CC13 GET / materialize are unaffected. Without the flag the snapshot
 * covers the single [address, address+length) range exactly as before. */
struct cmd_proc_turboscan_snap_segment {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
struct cmd_proc_turboscan_snap_plan {
    uint64_t slot_count;
    uint64_t total_bytes;
} __attribute__((packed));
struct cmd_proc_turboscan_snap_summary {
    uint32_t snapshot_ok;
    uint64_t survivor_count;
} __attribute__((packed));

/* TURBOSCAN_GET (CC13): fetch resident survivors [start_index, start_index+count).
 * Reply: uint32 hdr, then (hdr & 0x7FFFFFFF) records, then CMD_SUCCESS.
 *   hdr low 31 bits = actual_count (<= requested); hdr bit 31 = records carry the
 *   first-scan value (3-value shape). Record:
 *     bit31 clear: { uint64 addr; value current; value previous }   (8 + 2*value_length)
 *     bit31 set:   { uint64 addr; value current; value previous; value first } (8 + 3*value_length)
 *   current = the matched (last-scan) value from the session value store, NOT a live re-read
 *   (matches every other scan path; the client refreshes to live itself); previous = the prior-scan value (the value at the scan
 *   BEFORE the most recent one) when the session was started with TS_SNAPSHOT_KEEP_PREVIOUS,
 *   else the last-scan value (the snapshot/list value store, ~= current); first = value at
 *   snapshot create, present only for a session started with TS_SNAPSHOT_KEEP_FIRST (else
 *   bit 31 is clear and there is no first field).
 * valueType/value_length come from the session. */
struct cmd_proc_turboscan_get_packet {
    uint32_t start_index;
    uint32_t count;
    uint32_t flags;
} __attribute__((packed));

struct cmd_proc_scan_get_packet {
    uint32_t pid;
    uint32_t count;
} __attribute__((packed));

struct cmd_proc_scan_aob_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t  max_matches;
    uint8_t  stop_flag;
    uint32_t pattern_length;
} __attribute__((packed));

struct cmd_proc_scan_aob_multi_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint8_t  stop_flag;
    uint32_t patterns_length;
} __attribute__((packed));

struct cmd_proc_scan_packet {
    uint32_t pid;
    uint8_t  valueType;
    uint8_t  compareType;
    uint32_t lenData;
} __attribute__((packed));

struct cmd_proc_elf_rpc_packet {
    uint32_t pid;
    uint32_t length;
} __attribute__((packed));
#define CMD_PROC_ELF_RPC_PACKET_SIZE 8
struct cmd_proc_elf_rpc_response {
    uint64_t entry;
} __attribute__((packed));
#define CMD_PROC_ELF_RPC_RESPONSE_SIZE 8

struct cmd_proc_disasm_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint32_t max_entries;
} __attribute__((packed));
#define CMD_PROC_DISASM_PACKET_SIZE 20

struct cmd_proc_xrefs_to_packet {
    uint32_t pid;
    uint64_t scan_address;
    uint32_t scan_length;
    uint64_t target_address;
} __attribute__((packed));
#define CMD_PROC_XREFS_TO_PACKET_SIZE 24

struct disasm_instr_entry {
    uint64_t addr;
    uint64_t rip_rel_target;
    int64_t  mem_disp;
    uint8_t  length;
    uint8_t  kind;
    uint8_t  mem_base_reg;
    uint8_t  mem_index_reg;
    uint8_t  mem_scale;
    uint8_t  mnemonic_lo;
    uint16_t pad;
} __attribute__((packed));
#define DISASM_INSTR_ENTRY_SIZE 32

#define CMD_PROC_AUTH_MAGIC        0xBB40E64Du
#define CMD_PROC_AUTH_MAGIC_BSWAP  0x7780D98Eu
struct cmd_proc_auth_packet {
    uint32_t magic;
    uint32_t flags;
} __attribute__((packed));

struct cmd_proc_info_packet {
    uint32_t pid;
} __attribute__((packed));
struct cmd_proc_info_response {
    uint32_t pid;
    char     name[40];
    char     path[64];
    char     titleid[16];
    char     contentid[64];
} __attribute__((packed));

#define CMD_DEBUG_ATTACH        0xBDBB0001u
#define CMD_DEBUG_SET_BREAKPOINT 0xBDBB0003u
#define CMD_DEBUG_SET_WATCHPOINT 0xBDBB0004u

#define CMD_INVALID_INDEX   0xF000000Au

#define MAX_BREAKPOINTS     30
#define MAX_WATCHPOINTS     4

struct cmd_debug_breakpt_packet {
    uint32_t index;
    uint32_t enabled;
    uint64_t address;
} __attribute__((packed));
#define CMD_DEBUG_BREAKPT_PACKET_SIZE 16

struct cmd_debug_watchpt_packet {
    uint32_t index;
    uint32_t enabled;
    uint32_t length;
    uint32_t breaktype;
    uint64_t address;
} __attribute__((packed));
#define CMD_DEBUG_WATCHPT_PACKET_SIZE 24

struct cmd_debug_attach_packet {
    uint32_t pid;
} __attribute__((packed));
#define CMD_DEBUG_ATTACH_PACKET_SIZE 4

#endif
