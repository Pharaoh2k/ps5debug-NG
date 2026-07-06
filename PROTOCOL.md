# ps5debug-NG - Wire Protocol Reference

Developer-facing reference for every command exposed by the debugger payload.
The opcodes, struct layouts, sizes, and behaviours below are taken directly from
the sources under `debugger/source/`, `common/`, and the client
`Cheater-NG/CheaterNG/PS4DBG.cs`, with file + function citations. Where a server
value and the on-the-wire value differ (see the bit-swap note in 1.6), both are
given.

This document reflects `ps5debug-NG v1.3.1` (`common/include/version.h`,
`PS5DEBUG_NG_VERSION_STR`). The on-wire **protocol** version reported by
`CMD_VERSION` is a separate string, currently `"1.3"`.

---

## 1. Wire protocol fundamentals

### 1.1 Core constants

| Symbol             | Value                            | Source                                                   |
|--------------------|----------------------------------|----------------------------------------------------------|
| protocol version   | `"1.3"`                          | `meta.c` `handle_version` (local `char ver[]="1.3"`)     |
| branding string    | `"ps5debug-NG by OSR v1.3.1\01.0"` | `version.h` `PS5DEBUG_NG_BRAND_STR` via `meta.c` `handle_branding` (NUL-separated capability level appended - see 2.1) |
| `PACKET_MAGIC`     | `0xFFAABBCC`                     | `main.c:50` (local `#define`)                            |
| broadcast magic    | `0xFFFFAAAA`                     | `main.c` `broadcast_thread` (raw literal)                |
| auth magic         | `0xBB40E64D`                     | `protocol.h:249` (`CMD_PROC_AUTH_MAGIC`)                 |

None of these are defined in `protocol.h` except the auth magic. There is no
`server.h` / `server.c` in this tree; the framing, dispatch, and discovery code
lives in `main.c` and `meta.c`.

### 1.2 Ports

| Port | Protocol | Role                                                     | Source                              |
|------|----------|----------------------------------------------------------|-------------------------------------|
| 744  | TCP      | Main command server                                      | `main.c` `start_server` (`SERVER_PORT`) |
| 755  | TCP      | Async debug-interrupt channel (server connects out to client) | `debug.c` `connect_debugger` (`htons(755)`) |
| 3232 | TCP      | Kernel-log forwarder (server listens; streams `/dev/klog`) | `console.c` `klog_server_thread` (`sin_port=0xA00C`) |
| 1010 | UDP      | Discovery broadcast                                      | `main.c` `broadcast_thread` (port `0x3F2`) |

### 1.3 Byte order

All multi-byte integers are **little-endian** (native x86-64 layout).
`__attribute__((packed))` is used on every wire struct, so there is no implicit
padding between fields. (Exception: status words are bit-swapped on the wire,
see 1.6.)

### 1.4 Packet framing

Every request on port 744 begins with a fixed 12-byte header. `void *data` in the
C struct is NOT on the wire - it is a server-side pointer assigned after the
body is received (`protocol.h:26-31`, `main.c` `handle_client`):

```
struct cmd_packet {        // 12 bytes on the wire
    uint32_t magic;        // must equal PACKET_MAGIC (0xFFAABBCC)
    uint32_t cmd;          // command ID (see 4)
    uint32_t datalen;      // length of request body that follows the header
    void    *data;         // NOT transmitted; server-side pointer only
};
#define CMD_PACKET_SIZE 12
```

Framing loop (`main.c` `handle_client`, lines 70-155):

1. Each connection is serviced on its own thread. The thread `select()`s the
   socket and blocking-reads 12 bytes into a `cmd_packet` header.
2. Validates `magic == PACKET_MAGIC`; on mismatch the packet is silently dropped
   and the loop continues (no error response).
3. If `datalen != 0`: when `datalen > 0x100000` (1 MiB) the server sends the raw
   status literal `0xF0000002` (which is `CMD_ERROR` on the wire, see 1.6) and
   continues; otherwise it `malloc(datalen)`s a buffer and reads exactly
   `datalen` bytes into `packet.data`. (It uses `malloc`, not `net_alloc_buffer`.)
4. If the command is in the debug namespace (`(cmd & 0xFFFF0000) == 0xBDBB0000`),
   it is dispatched while holding both `g_proc_rw_mutex` and `g_server_mutex`.
5. `cmd_handler` dispatches to the namespace handler. A handler may read
   *additional* trailing data from the socket beyond the fixed request struct
   (writes, ELF images, register blobs, scan payloads), and several handlers
   reply with an intermediate `CMD_SUCCESS` *before* the data phase and a final
   status *after* it (see 8).

### 1.5 Dispatch routing (`meta.c` `cmd_handler`, lines 54-73)

`cmd_handler` inlines five infrequent commands, then routes everything else by
testing the command's **middle byte** (bits 16-23) against the `VALID_*_CMD`
macros:

| Namespace      | Predicate           | Dispatch target  | File        |
|----------------|---------------------|------------------|-------------|
| Info/ping      | n/a (inlined)       | `cmd_handler`    | `meta.c` (5 cases) |
| Process        | `VALID_PROC_CMD`    | `proc_handle`    | `proc.c`    |
| Debug          | `VALID_DEBUG_CMD`   | `debug_handle`   | `debug.c`   |
| Kernel R/W     | `VALID_KERN_CMD`    | `kern_handle`    | `kern.c`    |
| Console        | `VALID_CONSOLE_CMD` | `console_handle` | `console.c` |

`VALID_CMD(cmd)` first requires the top byte to be `0xBD`
(`protocol.h:20`); a command failing that returns immediately. `debug_handle` is
a weak symbol and is only called if linked in.

**Attach special case:** in `main.c handle_client` (lines 112-115), when
`cmd == CMD_DEBUG_ATTACH` and no session is active (`g_debug_attached == 0`), the
server records the current client slot into the globals `curdbgcli` /
`curdbgctx` before dispatching. The attach itself is then handled normally by
`debug_attach_handle` (see 2.3). There is no separate `_svc` handler.

### 1.6 Status codes and the bit-swap

The server transmits every `uint32_t` status word through `net_send_int32`
(`net.c:39`), which bit-swaps adjacent even/odd bit positions:

```c
static inline uint32_t bitswap32(uint32_t x) {
    return ((x >> 1) & 0x55555555u) | ((x << 1) & 0xAAAAAAAAu);  // involution
}
```

So the **server-side macro value** (`protocol.h:9-12`, `CMD_INVALID_INDEX` at
`:271`) and the **on-the-wire value** a client compares against differ. The swap is applied **only** to status
words; response payloads, length prefixes, struct bodies, and raw memory are
sent unswapped. Clients do **not** un-swap - they compare the raw wire word
directly to the post-swap constants (`PS4DBG.cs` `CMD_STATUS` + `ReceiveStatus`).

| Name                | Server macro (`protocol.h`) | On-the-wire value (clients compare this) |
|---------------------|-----------------------------|------------------------------------------|
| `CMD_SUCCESS`       | `0x40000000`                | `0x80000000`                             |
| `CMD_ERROR`         | `0xF0000002`                | `0xF0000001`                             |
| `CMD_DATA_NULL`     | `0xF0000003`                | `0xF0000003`                             |
| `CMD_ALREADY_DEBUG` | `0xF0000008`                | `0xF0000004`                             |
| `CMD_INVALID_INDEX` | `0xF000000A`                | `0xF0000005`                             |

Notes:
- There is **no** `CMD_TOO_MUCH_DATA` macro and **no** `CMD_FATAL_STATUS` macro
  in this tree. The over-size guard (1.4 step 3) sends the literal `0xF0000002`,
  which is `CMD_ERROR` on the wire (`0xF0000001`). The client's
  `CMD_TOO_MUCH_DATA = 0xF0000002` enum value is therefore never actually
  received.
- The auth magic uses the same swap: the server checks
  `bitswap32(packet magic) == CMD_PROC_AUTH_MAGIC_BSWAP (0x7780D98E)`, i.e. the
  client sends the raw `0xBB40E64D`.

### 1.7 Discovery (`main.c` `broadcast_thread`, lines 174-218)

A UDP server on port 1010 receives 4-byte datagrams. If the payload equals
`0xFFFFAAAA`, the server echoes the same 4 bytes back to the sender. No other
payload is acted on; there is no authentication on this channel. (`PS4DBG.cs`
`FindPlayStation` broadcasts the magic and matches the echo.)

### 1.8 Authentication (`auth.c` `proc_auth_handle`)

A single **global** flag word `g_proc_auth_state` (`auth.c:13`, default
`0x14000`) gates the *stateful* scan trio. Bit 1 (`0x02`) is the scan-enabled
bit; `CMD_PROC_SCAN_START` / `_COUNT` / `_GET` check `g_proc_auth_state & 2` on
entry (`scan.c:351`, `:475`, `:620`). The legacy/AOB scans
(`CMD_PROC_SCAN`, `CMD_PROC_SCAN_AOB`, `CMD_PROC_SCAN_AOB_MULTI`) do **not**
check it. The flag is global and is **not** reset on disconnect.

`CMD_PROC_AUTH` (`0xBDAACCFF`) handshake:

1. Client sends `struct cmd_proc_auth_packet` (`protocol.h:251`):
   `uint32_t magic` (raw `0xBB40E64D`) + `uint32_t flags`.
2. Server validates the magic (1.6) and replies `CMD_SUCCESS`.
3. Server sends `uint16_t challenge_length = 64`, then 64 challenge bytes
   (derived from an internal xorshift-128 generator).
4. Client XORs the challenge against a fixed keystream (xorshift-128 seeded with
   `200,300,400,500`; see `PS4DBG.cs` `GenerateKeystream`) and sends 64 response
   bytes back.
5. On a byte-exact match the server sets the flag word - `flags & 1` ->
   `0x14001`, `flags & 2` -> `0x14002` (scan-enabled) - and replies
   `CMD_SUCCESS`; otherwise `CMD_DATA_NULL`. (`PS4DBG.cs` `ValidateProcess`
   passes `flags = maxLength`, whose bit 1 is set, enabling scans.)

### 1.9 Asynchronous interrupt channel (port 755)

On `CMD_DEBUG_ATTACH`, the server opens a TCP connection *outbound* to the
client's IP on port 755 (`debug.c` `connect_debugger`, `htons(755)`). The client
must be listening on 755 before attaching (`PS4DBG.cs` `DebuggerThread` binds
`0.0.0.0:755`).

Breakpoint/watchpoint hits and single-step completions are delivered as
fixed-size 1184-byte (`0x4A0`) packets. There is **no** named struct or size
macro in the server source for this - the packet is assembled by hand at fixed
offsets in `debug.c` `dispatch_debug_events` (lines 1189-1240). The layout is:

```
offset  size  field
0x000     4   uint32_t lwpid
0x004     4   uint32_t status                 // raw wait4 status word
0x008    40   char     tdname[40]             // ~24 bytes copied from PT_LWPINFO pl_tdname
0x030   176   struct reg   reg64              // FreeBSD amd64 GP registers
0x0E0   832   struct fpu   savefpu            // FPU + YMM
0x420   128   struct dbreg dbreg64            // 16 x uint64_t
                                              // total = 0x4A0 = 1184
```

The matching client struct is `PS4DBG.cs` `DebuggerInterruptPacket`
(`tdname[40]`, `regs` 176, `fpregs` 832, `dbregs` 128). `savefpu` lands at offset
`0xE0` (224); the struct is packed so it is not 64-byte aligned, which is
intentional.

---

## 2. Command reference

69 opcodes have handlers. Only a handful are given `CMD_*` macros in
`protocol.h` (`CMD_VERSION`, `CMD_FW_VERSION`, `CMD_BRANDING`, `CMD_PLATFORM_ID`,
`CMD_PROC_NOP`, `CMD_DEBUG_ATTACH`, `CMD_DEBUG_SET_BREAKPOINT`,
`CMD_DEBUG_SET_WATCHPOINT`); the rest are bare hex literals inside the
per-namespace `switch` statements. Three opcodes have no symbolic name at all:
`0xBDAA000D`, `0xBDAA0024`, `0xBDDD0006`.

### 2.1 Info & ping - inlined in `cmd_handler` (`meta.c:60-64`)

#### `CMD_VERSION = 0xBD000001`
- **Request body:** none.
- **Response:** `uint32_t length`, then `length` bytes of the protocol version
  string ("1.3"). No status word precedes it.

#### `CMD_FW_VERSION = 0xBD000500`
- **Request body:** none.
- **Response:** `uint16_t` firmware as a **decimal** number (the BCD high word of
  `kernel_get_fw_version()` converted digit-by-digit), e.g. `900` for 9.00,
  `1240` for 12.40, `505` for 5.05. No status word precedes it.

#### `CMD_BRANDING = 0xBD000501`
- **Request body:** none.
- **Response:** `uint32_t length`, then `length` bytes: the human branding string
  (`"ps5debug-NG by OSR v1.3.1"`), a single `NUL`, then a **capability level**
  string (`"1.0"`), with no trailing NUL. No status word precedes it. (The client
  calls this `CMD_EXT_VERSION`.)
- **Capability level:** C-string clients read up to the first `NUL` and see only
  the unchanged brand; capability-aware clients read the bytes past the `NUL` to
  get the level. The level is bumped as the server gains negotiable features (so a
  client can gate a feature on the server advertising at least a given level).
  Built from `PS5DEBUG_NG_BRAND_STR "\0" "1.0"` in `meta.c` `handle_branding` -
  the literals are split (`"\0" "1.0"`) so `\0` is a NUL byte, not the octal
  escape `\01`.

#### `CMD_PLATFORM_ID = 0xBD000502`
- **Request body:** none.
- **Response:** `uint16_t`, hardcoded `5`. No status word precedes it. (Present
  in the server only; the CheaterNG client does not invoke it.)

#### `CMD_PROC_NOP = 0xBDAACC06`
- **Request body:** none.
- **Response:** `CMD_SUCCESS`. Keepalive / liveness probe (client `Ping`).

---

### 2.2 Process commands - dispatched by `proc_handle` (`proc.c:958-993`)

Unless noted, the request body is read into `packet->data` up front; "trailing
data" is read from the socket by the handler after a leading `CMD_SUCCESS`.

#### `CMD_PROC_LIST = 0xBDAA0001` (`proc.c:364`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`, `uint32_t num` (4 bytes), then `num` x
  `struct proc_list_entry { char name[32]; int32_t pid; }` (36 bytes each,
  `protocol.h:43`). The list is built by walking the kernel `allproc` chain.

#### `CMD_PROC_READ = 0xBDAA0002` (`proc.c:440`)
- **Request body:** `struct cmd_proc_read_packet` (16 bytes).
- **Response:** `CMD_SUCCESS`, then up to `length` bytes in 64 KiB (`0x10000`)
  chunks.

#### `CMD_PROC_WRITE = 0xBDAA0003` (`proc.c:563`)
- **Request body:** `struct cmd_proc_write_packet` (16 bytes).
- **Response:** `CMD_SUCCESS` (before the data phase), then the server reads
  `length` bytes in 64 KiB chunks, then `CMD_SUCCESS` again. **Two** status
  words (see 8).

#### `0xBDAACC04` (`proc_write_multi_handle`)
Bulk write - the write counterpart to `0xBDAACC03` (bulk read). Collapses a
freeze / multi-poke loop of N single `CMD_PROC_WRITE`s into one exchange. Dispatched
by `proc_handle`; **not** auth-gated (mirrors single write).
- **Request body:** `struct cmd_proc_write_multi_packet` (12 bytes,
  `{ uint32_t pid; uint32_t count; uint32_t flags; }`). `flags` bit 0
  (`PROC_WRITE_MULTI_F_STATUS`) requests a per-entry status array in the response.
- **Trailing data:** after the server's first `CMD_SUCCESS`, the client streams
  `count` entries, each `{ uint64_t address; uint32_t length; <length> bytes data }`
  concatenated. Per-entry `length` is capped at `0x100000`; `count` at `0xFFFF`.
- **Response:** `CMD_SUCCESS` (ack), then the server reads and applies each entry
  (writing via the same DMAP / mdbg path as `CMD_PROC_WRITE`, in 64 KiB chunks).
  If `flags` bit 0 was set, it then sends a `count`-byte status array (one byte per
  entry, `0` = ok, `1` = write failed). Finally a trailing `CMD_SUCCESS`. **Two**
  status words, plus the optional status array between them.
- **Semantics:** best-effort and non-atomic - entries are applied in order and a
  failed entry does not stop the rest. Without the status flag, individual write
  failures are not reported (same as single `CMD_PROC_WRITE`, whose underlying
  `proc_write_mem` is `void`). A `count`/`length` cap violation makes the server
  reply `CMD_ERROR` and abort the command (the connection's stream is then
  untrustworthy; well-behaved clients stay within the caps).

#### `CMD_PROC_MAPS = 0xBDAA0004` (`proc.c:597`)
- **Request body:** `struct cmd_proc_maps_packet` (4 bytes, `pid`).
- **Response:** `CMD_SUCCESS`, `uint32_t num`, then `num` x
  `struct proc_vm_map_entry` (**58 bytes** each, `protocol.h:154`):
  `{ char name[32]; uint64_t start; uint64_t end; uint64_t offset; uint16_t prot; }`.
  The map may be augmented by a kernel page-table walk (`proc_ptwalk_augment`)
  before sending.

#### `CMD_PROC_INTALL = 0xBDAA0005` (`proc.c:648`)
Literal spelling `INTALL` (typo preserved on the wire).
- **Request body:** `struct cmd_proc_install_packet` (4 bytes, `pid`).
- **Response:** `CMD_SUCCESS`, then `uint64_t rpcstub = 0`.
- **Note:** in this build the handler is a **stub** - it returns `rpcstub = 0`
  and performs no injection.

#### `CMD_PROC_CALL = 0xBDAA0006` (`proc.c:659`)
- **Request body:** `struct cmd_proc_call_packet` (68 bytes):
  `uint32_t pid; uint64_t rpcstub, rpc_rip, rpc_rdi, rpc_rsi, rpc_rdx, rpc_rcx, rpc_r8, rpc_r9;`
- **Response:** `CMD_SUCCESS`, then `struct cmd_proc_call_response`
  `{ uint32_t pid; uint64_t rpc_rax; }` (12 bytes). On backend failure the
  handler returns `-1` with no status word (the connection is then torn down).

#### `CMD_PROC_ELF = 0xBDAA0007` (`proc.c:691`)
- **Request body:** `struct cmd_proc_elf_packet` `{ uint32_t pid; uint32_t length; }` (8 bytes).
- **Response:** `CMD_SUCCESS` (before data), reads `length` bytes of ELF, then
  `CMD_SUCCESS` or `CMD_ERROR`. **Two** status words.

#### `CMD_PROC_PROTECT = 0xBDAA0008` (`proc.c:769`)
- **Request body:** `struct cmd_proc_protect_packet` (20 bytes, defined in
  `proc.c:762`): `{ uint32_t pid; uint64_t address; uint32_t length; uint32_t prot; }`.
- **Response:** `CMD_SUCCESS` or `CMD_ERROR` (single status).

#### `CMD_PROC_SCAN = 0xBDAA0009` (`scan.c:82`)
Legacy single-pass scan. **No auth required.**
- **Request body:** `struct cmd_proc_scan_packet` (10 bytes):
  `{ uint32_t pid; uint8_t valueType; uint8_t compareType; uint32_t lenData; }`.
- **Trailing data:** `lenData` bytes of comparison value(s).
- **Response:** `CMD_SUCCESS` (ack), the server reads the value, scans, sends
  `CMD_SUCCESS` again, then **streams** matching addresses as `uint64_t`s
  terminated by an all-`0xFF` sentinel `0xFFFFFFFFFFFFFFFF`. No count prefix.
  (Compare via `scan_compare.c` `proc_scan_legacy_compareValues`.)

#### `CMD_PROC_INFO = 0xBDAA000A` (`proc.c:790`)
- **Request body:** `struct cmd_proc_info_packet` (4 bytes, `pid`).
- **Response:** `CMD_SUCCESS`, `struct cmd_proc_info_response` (**188 bytes**,
  `protocol.h:259`): `{ uint32_t pid; char name[40]; char path[64]; char titleid[16]; char contentid[64]; }`.
  `titleid`/`contentid` are resolved by `sceKernelGetAppInfo` plus a pattern scan
  of the proc struct, falling back to per-firmware offsets
  (`proc_field_offsets.c`).

#### `CMD_PROC_ALLOC = 0xBDAA000B` (`proc.c:853`)
- **Request body:** `struct cmd_proc_alloc_packet` (8 bytes, `{ pid, length }`).
- **Response:** `CMD_SUCCESS`, `struct cmd_proc_alloc_response` `{ uint64_t address; }` (8 bytes).

#### `CMD_PROC_FREE = 0xBDAA000C` (`proc.c:880`)
- **Request body:** `struct cmd_proc_free_packet` (16 bytes, `{ pid, address, length }`).
- **Response:** `CMD_SUCCESS`.

> **Alloc arena (default ON).** A plain `CMD_PROC_ALLOC` is served from a server-side
> per-pid 16 MB arena: one hijacking `mmap` per segment, then zero-hijack sub-allocation
> (with `CMD_PROC_FREE` recycling the slice into a free-list). This avoids the thread-hijack
> crash hazard that pathological concurrent allocation otherwise triggers. It is fully
> transparent (same wire, valid target addresses); a freed sub-block is recycled rather than
> `munmap`'d, and the segment is reclaimed when the game exits. `CMD_PROC_ALLOC_HINTED`
> (which needs a specific address) bypasses the arena and allocates directly. The arena can
> be toggled at runtime via the raw literal `0xBDAACC24` (`proc_arena_handle`): request body
> `uint32_t` (`1` = enable, `0` = disable), response `CMD_SUCCESS` + `uint32_t len` + a text
> status line.

#### `0xBDAA000D` - first-map probe (`proc.c:901`, `proc_unknown_d_handle`)
Raw literal, no `CMD_*` macro.
- **Request body:** `struct cmd_proc_unknown_d_packet` (4 bytes, `pid`).
- **Response:** `CMD_SUCCESS` then `uint64_t` = the `start` address of the
  target's first VM map entry, or `CMD_ERROR` if the map could not be read.

#### `CMD_PROC_ALLOC_HINTED = 0xBDAA000E` (`proc.c:929`)
- **Request body:** `struct cmd_proc_alloc_hinted_packet` (16 bytes, `{ pid, hint, length }`).
- **Response:** `CMD_SUCCESS` + `struct cmd_proc_alloc_response` on success; on
  failure it sends `CMD_ERROR` **and still** the (zeroed/partial) response struct.

#### `CMD_PROC_ELF_RPC = 0xBDAA0010` (`proc.c:724`)
Like `CMD_PROC_ELF` but returns the entry address instead of jumping into it.
- **Request body:** `struct cmd_proc_elf_rpc_packet` (8 bytes, `{ pid, length }`).
- **Response:** `CMD_SUCCESS` (before data), reads `length` ELF bytes, then
  `CMD_SUCCESS` + `struct cmd_proc_elf_rpc_response` `{ uint64_t entry; }` (8
  bytes). **Two** status words.

#### `CMD_PROC_DISASM_REGION = 0xBDAA0020` (`proc.c:197`)
- **Request body:** `struct cmd_proc_disasm_packet` (20 bytes, `{ pid, address, length, max_entries }`).
- **Validation:** `max_entries` must be `1 .. 1000000`, else `CMD_ERROR`.
- **Response:** `CMD_SUCCESS`, then a stream of `struct disasm_instr_entry` (32
  bytes each), terminated by a 32-byte sentinel with all bytes `0xFF`.
- **Backend:** Zydis (`third_party/zydis/Zydis.c`).

`disasm_instr_entry` (`protocol.h:235`):
```
struct disasm_instr_entry {   // 32 bytes
    uint64_t addr;              // instruction start
    uint64_t rip_rel_target;    // resolved absolute addr if RIP-relative; else 0
    int64_t  mem_disp;          // [base + index*scale + disp]
    uint8_t  length;
    uint8_t  kind;              // bitmask below
    uint8_t  mem_base_reg;      // ZydisRegister low byte; 0 if none
    uint8_t  mem_index_reg;
    uint8_t  mem_scale;         // 1/2/4/8; 0 if none
    uint8_t  mnemonic_lo;       // ZydisMnemonic low byte
    uint16_t pad;
};
```

Kind bitmask (`proc.c` `disasm_fill_entry`):
| Bit  | Meaning                            |
|------|------------------------------------|
| 0x01 | `CALL`                             |
| 0x02 | `RET`                              |
| 0x04 | Unconditional `JMP`                |
| 0x08 | Conditional branch                 |
| 0x10 | Has a memory operand               |
| 0x20 | Memory operand is RIP-relative     |
| 0x40 | Memory read                        |
| 0x80 | Memory write                       |

#### `CMD_PROC_EXTRACT_CODE_XREFS = 0xBDAA0021` (`proc.c:262`)
- **Request body:** `struct cmd_proc_disasm_packet` (20 bytes); if `max_entries`
  is 0 a default of 10000000 is used.
- **Response:** `CMD_SUCCESS`, then a **stream** of `uint64_t` RIP-relative
  target addresses (one per RIP-relative memory operand encountered; not
  de-duplicated by the server), terminated by a `0xFFFFFFFFFFFFFFFF` sentinel.
  No count prefix.

#### `CMD_PROC_FIND_XREFS_TO = 0xBDAA0022` (`proc.c:325`)
- **Request body:** `struct cmd_proc_xrefs_to_packet` (24 bytes):
  `{ uint32_t pid; uint64_t scan_address; uint32_t scan_length; uint64_t target_address; }`.
- **Response:** `CMD_SUCCESS`, then a **stream** of `uint64_t` instruction
  addresses whose resolved RIP-relative target equals `target_address`,
  terminated by a `0xFFFFFFFFFFFFFFFF` sentinel. No count prefix, no kind byte.

#### `CMD_PROC_READ_STACK = 0xBDAA0023` (`proc.c:485`)
Server-side RBP-chain walk: the server walks the frame chain and bundles each
frame's saved RBP, return address, frame-local bytes, and a code window around
the return address into one response.
- **Request body:** `struct cmd_proc_read_stack_packet` (24 bytes):
  `{ uint32_t pid; uint64_t rbp; uint64_t rsp; uint32_t depth; }`
  - `rbp`/`rsp` describe the local (top) frame; `depth` caps frames returned.
- **Response:** `CMD_SUCCESS`, `uint32_t bundle_len`, then `bundle_len` bytes:
  ```
  u32 n_frames
  per frame {
      u64 rbp; u64 rsp; u64 saved_rbp; u64 ret_addr;
      u32 flags;            // bit0: frame-locals omitted (oversized/invalid)
      u32 frame_locals_len;
      u32 code_len;         // bytes of code at (ret_addr - 10); 0 if unavailable
      u8  frame_locals[frame_locals_len];
      u8  code[code_len];
  }
  ```
  - Caps (`protocol.h:89-93`): `MAX_DEPTH = 64`, `LOCALS_CAP = 0x1000` per frame,
    `CODE_OFF = 10`, `CODE_LEN = 200`.

#### `0xBDAA0024` - assemble x86-64 (`assemble.c` `proc_assemble_handle`)
Raw literal, no `CMD_*` macro. Assembles x86-64 text into machine bytes using the
embedded Keystone (LLVM-MC) assembler. Pure userspace; no attached process
required.
- **Request body** (in `packet->data`; `datalen` must be `>= 12`): a 12-byte
  header `struct cmd_proc_assemble_packet` `{ uint64_t base_addr; uint32_t ks_opt_syntax; }`
  followed by `(datalen - 12)` bytes of asm text (NUL-termination not required).
  - `base_addr` is what Keystone resolves PC-relative operands against.
  - `ks_opt_syntax = 0` keeps the engine default (Intel); a non-zero value is
    passed straight to `ks_option(KS_OPT_SYNTAX, ...)`.
- **Response on success:** `CMD_SUCCESS`, `struct cmd_proc_assemble_ok`
  `{ uint32_t byte_len; uint32_t insn_count; }` (8 bytes), then `byte_len`
  machine-code bytes.
- **Response on assembler error:** `CMD_ERROR`, `struct cmd_proc_assemble_err`
  `{ uint32_t ks_errno; uint32_t msg_len; }` (8 bytes), then `msg_len` bytes of
  the `ks_strerror` message.

#### `CMD_PROC_SCAN_AOB = 0xBDAA0501` (`scan.c:151`)
Array-of-bytes single scan. **No auth required.**
- **Request body:** `struct cmd_proc_scan_aob_packet` (22 bytes):
  `{ uint32_t pid; uint64_t address; uint32_t length; uint8_t max_matches; uint8_t stop_flag; uint32_t pattern_length; }`.
- **Trailing data:** `pattern_length` pattern bytes, then `pattern_length` mask
  bytes (mask byte `1` = must match; any other value = wildcard).
- **Response:** `CMD_SUCCESS` (ack), reads pattern+mask, `CMD_SUCCESS` again,
  scans, then sends a single `uint64_t` = the `max_matches`-th match address
  (or `0` if not found, or if `stop_flag == 1` and the match is not unique),
  then `CMD_SUCCESS`.

#### `CMD_PROC_SCAN_AOB_MULTI = 0xBDAA0502` (`scan.c:237`)
Multi-pattern AOB scan. **No auth required.** (Client name: `CMD_PROC_SCAN_AOB_ALL`.)
- **Request body:** `struct cmd_proc_scan_aob_multi_packet` (21 bytes):
  `{ uint32_t pid; uint64_t address; uint32_t length; uint8_t stop_flag; uint32_t patterns_length; }`.
- **Trailing data:** `patterns_length` bytes of concatenated patterns; each
  pattern is `[uint8_t target_count][uint32_t pattern_length][pattern_length pattern bytes][pattern_length mask bytes]`.
- **Response:** `CMD_SUCCESS` (ack), reads the blob, `CMD_SUCCESS` again, scans,
  then sends `pat_count` x `uint64_t` (one match address per pattern, `0` if
  none / invalidated), then `CMD_SUCCESS`. (The client supplies `pat_count` and
  reads exactly that many `uint64_t`s.)

#### `CMD_PROC_AUTH = 0xBDAACCFF` (`auth.c:60`)
See 1.8.

#### `CMD_PROC_SCAN_START = 0xBDAACC01` (`scan.c:350`) - **requires auth bit 1**
First pass of the staged scanner. (Client name: `CMD_PROC_SCAN_INIT`.)
- **Request body:** `struct cmd_proc_scan_start_packet` (23 bytes):
  `{ uint32_t pid; uint64_t address; uint32_t length; uint8_t valueType; uint8_t compareType; uint8_t alignment; uint32_t lenData; }`.
- **Trailing data:** the seed value(s) when the compare type needs them, plus a
  mask when `valueType == 10` (arrBytes).
- **Response:** `CMD_SUCCESS` (ack), reads value/mask, `CMD_SUCCESS` again, then
  **streams** result blocks - each block is `uint64_t block_len` followed by
  `block_len` bytes of `(uint32_t offset, value)` entries (`offset` is relative
  to `address`) - terminated by a `0xFFFFFFFFFFFFFFFF` sentinel, then a final
  `CMD_SUCCESS`. The result set lives **on the client**; the server keeps no
  per-pid session.

#### `CMD_PROC_SCAN_COUNT = 0xBDAACC02` (`scan.c:474`) - **requires auth bit 1**
Filtering pass: the client streams its current candidate list back and the
server returns the survivors. (Client name: `CMD_PROC_SCAN_NEXT`.)
- **Request body:** `struct cmd_proc_scan_count_packet` (18 bytes):
  `{ uint32_t pid; uint64_t base_address; uint8_t valueType; uint8_t compareType; uint32_t lenData; }`.
- **Trailing data:** value/mask as for `SCAN_START`, then a client-driven loop of
  chunks: `uint32_t chunk_len` + `chunk_len` bytes of `(uint32_t offset[, prev_value])`
  entries. `chunk_len == 0xFFFFFFFF` ends the loop.
- **Response:** for each chunk the server re-reads memory, re-compares, and sends
  surviving `(offset, value)` entries as `uint64_t block_len`-prefixed blocks
  followed by a per-chunk `0xFFFFFFFFFFFFFFFF` sentinel. After the loop ends it
  sends a final `CMD_SUCCESS`.

#### `CMD_PROC_SCAN_GET = 0xBDAACC03` (`scan.c:619`) - **requires auth bit 1**
Bulk memory fetch for a candidate list. (Client name: `CMD_PROC_READ_MULTI`.)
- **Request body:** `struct cmd_proc_scan_get_packet` (8 bytes, `{ pid, count }`).
- **Trailing data:** `count` x `{ uint64_t address; uint32_t length; }` (12 bytes
  each).
- **Response:** `CMD_SUCCESS`, then the raw memory bytes for each entry
  concatenated in order, then a `0xFFFFFFFFFFFFFFFF` sentinel. (Returns raw
  memory, not addresses.)

#### TURBOSCAN family - `0xBDAACC10`-`0xBDAACC17` (`scan_turbo.c`)

Additive turbo-scan path (v1.3.0). The legacy (`0xBDAA0009`), AOB
(`0501`/`0502`), and iterative (`CC01`/`02`/`03`) scans are unchanged; a client
detects TURBOSCAN via `CMD_PROC_TURBOSCAN_CAPS` and falls back to the iterative
trio when it (or a specific engine bit) is absent. Result blocks reuse the
iterative `(offset, value)` shape so clients reuse one parser. IDs, engine bits,
and request flags are in `protocol.h:22-37`.

**Engine bits** (`CAPS` `engines` field):

| Bit    | Name                  | Meaning                                         |
|--------|-----------------------|-------------------------------------------------|
| `0x01` | `TSE_SIMD_COMPARE`    | typed AVX2 (256-bit) comparator                 |
| `0x02` | `TSE_ALIASING`        | physical-page aliasing read engine (opt-in)     |
| `0x04` | `TSE_SERVER_RESIDENT` | server-side survivor sets                       |
| `0x08` | `TSE_SNAPSHOT`        | unknown-initial-value bitmap + snapshot scans   |
| `0x10` | `TSE_SNAPSHOT_SEGMENTS` | trailing segment list of disjoint regions in one session (snapshot or resident `START`) |
| `0x20` | `TSE_SNAPSHOT_CONFIG`   | `CMD_PROC_TURBOSCAN_CONFIG` supported (RAM threshold + spill dir) |
| `0x40` | `TSE_SNAPSHOT_FIRST`    | `TS_SNAPSHOT_KEEP_FIRST` + CC13 GET returns the first-scan value (3-value records) |
| `0x80` | `TSE_SNAPSHOT_PREVIOUS` | `TS_SNAPSHOT_KEEP_PREVIOUS`: CC13 GET `previous` carries the prior-scan value (not the last-scan value) |
| `0x100` | `TSE_PARALLEL_COMPARE` | `TS_PARALLEL_COMPARE` supported (server-side multi-thread for the aliased SIMD exact-match streaming scan) |
| `0x200` | `TSE_RESCAN_ALIASING`  | `TS_RESCAN_ALIASING` supported (CC12 rescan reads full-size survivor windows via the aliasing engine) |

**Per-request flags** (`START` / `COUNT` `flags` field):

| Bit    | Name                 | Meaning                                                |
|--------|----------------------|--------------------------------------------------------|
| `0x01` | `TS_USE_ALIASING`    | use the aliasing read engine for this scan (default 0) |
| `0x02` | `TS_SERVER_RESIDENT` | keep / rescan the survivor set server-side             |
| `0x04` | `TS_SNAPSHOT`        | unknown-initial-value snapshot scan (`START` only)     |
| `0x08` | `TS_SNAPSHOT_INCLUDE_ZEROS` | snapshot: seed all-zero slots too - **default drops them** (`START` only) |
| `0x10` | `TS_SNAPSHOT_SEGMENTS` | scan covers a trailing segment list of disjoint regions, not `[address, length)` (`START` with `TS_SNAPSHOT` or `TS_SERVER_RESIDENT`) |
| `0x20` | `TS_SNAPSHOT_KEEP_FIRST` | retain an immutable first-scan value store so CC13 GET can return `first` (`START` + `TS_SNAPSHOT` only) |
| `0x40` | `TS_SNAPSHOT_KEEP_PREVIOUS` | retain a prior-scan value store so CC13 GET `previous` = value at the previous scan, not the just-matched one (`START` + `TS_SNAPSHOT` only) |
| `0x80` | `TS_PARALLEL_COMPARE` | split the scan across worker threads server-side - `START` + `TS_USE_ALIASING`, exact-match (compareType 0) streaming only. For **single-connection** clients; a multi-connection client should parallelize by opening more connections instead (the server threads per connection), and must **not** also set this (the two compose to over-subscription, which is slower). Ignored on any non-qualifying scan. |
| `0x100` | `TS_RESCAN_ALIASING` | `COUNT` rescans read full-size (gap-bridged, contiguous) survivor windows via the aliasing read engine instead of mdbg; tiny scattered windows and any alias failure fall back to mdbg (the floor). ~2-3x faster on dense/moderate-density rescans (the win grows as survivors stay dense; past ~32KB inter-survivor gaps windows fragment and it stays mdbg). Applies to all three CC12 rescan paths (snapshot-resident, list-resident, client-driven). The survivor set is **per-connection**, so this is single-connection by nature - a multi-connection client must **not** enable it on many connections at once (over-subscribes the aliasing setup, same caveat as `TS_PARALLEL_COMPARE`). |

##### `CMD_PROC_TURBOSCAN_CAPS = 0xBDAACC10` (`proc_turboscan_caps_handle`)
Capability probe. **No auth required.**
- **Request body:** none.
- **Response:** `CMD_SUCCESS`, then `struct cmd_proc_turboscan_caps_response`
  (16 bytes): `{ u32 version; u32 engines; u32 max_threads; u32 reserved; }`.
  `version = 1`; `engines` is the OR of the supported `TSE_*` bits; `max_threads`
  is the compare stage's worker count. An old server without TURBOSCAN never
  answers this opcode (or replies `CMD_ERROR`) - the client's fallback signal.

##### `CMD_PROC_TURBOSCAN_START = 0xBDAACC11` (`proc_turboscan_start_handle`) - **requires auth bit 1**
First scan; mirrors `CMD_PROC_SCAN_START` plus a trailing `flags` field and the
optional resident / snapshot / aliasing modes.
- **Request body:** `struct cmd_proc_turboscan_start_packet` (27 bytes):
  `{ u32 pid; u64 address; u32 length; u8 valueType; u8 compareType; u8 alignment; u32 lenData; u32 flags; }`.
- **Trailing data:** the seed value(s) when the compare type needs them, plus a
  mask when `valueType == 10` (as `SCAN_START`). `TS_SNAPSHOT` needs no seed. When
  `TS_SNAPSHOT_SEGMENTS` is set (with either `TS_SNAPSHOT` or `TS_SERVER_RESIDENT`),
  a segment list follows the value/mask (see the snapshot sub-protocol for the exact
  wire format; the resident variant reuses it verbatim).
- **Response (default, or `TS_USE_ALIASING`):** `CMD_SUCCESS` (ack), reads
  value/mask, `CMD_SUCCESS` again, then streams `(offset, value)` result blocks
  (`u64 block_len`-prefixed) terminated by a `0xFFFFFFFFFFFFFFFF` sentinel, then a
  final `CMD_SUCCESS` - the same shape as `SCAN_START`. `TS_USE_ALIASING` only
  changes how the server **reads** target memory (in place vs copied); the wire
  result is identical, and the engine silently falls back to the normal read path
  on any page it cannot alias. `TS_PARALLEL_COMPARE` (with `TS_USE_ALIASING`, exact-match
  streaming) additionally splits the scan across server worker threads - intended for
  single-connection clients; multi-connection clients should instead open more connections
  (the server threads per connection) and leave this flag clear. The wire result is identical
  either way.
- **Response (`TS_SERVER_RESIDENT`):** after the two acks the server stores
  survivors server-side and replies `struct cmd_proc_turboscan_resident_summary`
  (12 bytes): `{ u32 resident_stored; u64 count; }`, streaming **no** result
  blocks. If storage fails (overflow / too-wide value / mmap fail) it replies
  `resident_stored = 0` and then streams the full result set the normal way
  (transparent fallback). Closes with `CMD_SUCCESS`.
- **Response (`TS_SERVER_RESIDENT | TS_SNAPSHOT_SEGMENTS`, `TS_SNAPSHOT` clear):**
  multi-segment resident. After the two acks the server reads the trailing segment
  list (`u32 segment_count`, then `segment_count` x `cmd_proc_turboscan_snap_segment`,
  the **same** wire format and `1 .. 1048576` bound as the snapshot sub-protocol; the
  packet `address`/`length` are ignored), scans each disjoint segment, and appends all
  matches into the one resident session buffer (`count` accumulates across segments).
  Reply shape is unchanged: the 12-byte summary with `resident_stored = 1` and
  `count` = total matches, then `CMD_SUCCESS`. Survivors are stored as absolute
  `{ u64 addr; value }` records, so `CC12` narrow and `CC13` GET are unaffected by the
  segmentation. **Decline (no stream fallback):** if storage overflows
  `TS_RESIDENT_CAP`, the segment count is malformed, or an allocation fails, the server
  replies `resident_stored = 0, count = 0` followed by an **empty** result stream (an
  immediate `0xFFFFFFFFFFFFFFFF` sentinel, i.e. zero result blocks) and `CMD_SUCCESS` -
  byte-identical framing to the single-range transparent fallback, just with no blocks.
  A transparent server stream is **not** used here because a `u32` block offset cannot
  carry the absolute addresses of `>4 GiB`-scattered segments; the client treats
  `resident_stored = 0` on a segmented request as "server declined" and falls back to
  its own per-section streaming.
- **Response (`TS_SNAPSHOT`):** (with `TS_SNAPSHOT_SEGMENTS`, reads the trailing
  segment list first) streams the snapshot plan / progress / summary (see the
  snapshot sub-protocol below), then `CMD_SUCCESS`. If `TS_SNAPSHOT_KEEP_FIRST` is set,
  the server also writes an immutable **first-scan** value store at create (a spill-only
  file, never updated by narrowing) so CC13 GET can return the `first` column; it is
  needed for the count-only resident path where the client never saw the first-scan
  per-result values (a large unknown-value scan). It roughly doubles the value-store
  *disk* footprint (not RAM, since it is spill-only) and is freed when the session
  materialises to a list or ends. On first-store creation failure the snapshot still
  succeeds and GET falls back to the 2-value shape. If `TS_SNAPSHOT_KEEP_PREVIOUS` is set,
  the server also keeps a **prior-scan** value store (another spill-only file, rewritten
  each rescan with the baseline it held *before* that rescan), so CC13 GET's `previous`
  reflects the value at the scan before the most recent one (matching console/async
  semantics) instead of the just-matched value. Without it, `previous` is the last-scan
  value store (~= `current`). It is the costliest of the three stores (written every
  narrow); freed on materialise/end; degrades to the legacy `previous` on create failure.

##### `CMD_PROC_TURBOSCAN_COUNT = 0xBDAACC12` (`proc_turboscan_count_handle`) - **requires auth bit 1**
Rescan. Mirrors `CMD_PROC_SCAN_COUNT` (client-driven candidate chunks) unless
`TS_SERVER_RESIDENT` is set, in which case it rescans the server-resident set in
place (no candidate upload) and refreshes each survivor's baseline (so the next
rescan is "since last scan"). With `TS_RESCAN_ALIASING` set, full-size survivor
windows are read via the aliasing engine instead of mdbg (mdbg floor on small
windows / alias failure); wire format and results are unchanged.
- **Request body:** `struct cmd_proc_turboscan_count_packet` (22 bytes):
  `{ u32 pid; u64 base_address; u8 valueType; u8 compareType; u32 lenData; u32 flags; }`.
- **Trailing data:** value/mask as for `START` when needed; then, in the
  **client-driven** mode only, the same chunked candidate loop as `SCAN_COUNT`
  (`u32 chunk_len` + entries; `0xFFFFFFFF` ends it).
- **Response (client-driven):** identical to `SCAN_COUNT` - per-chunk
  `(offset, value)` blocks + per-chunk `0xFFFFFFFFFFFFFFFF` sentinel, then a final
  `CMD_SUCCESS`.
- **Response (`TS_SERVER_RESIDENT`):** **mode-independent** - both a list session and a
  snapshot session reply with the same shape: a **progress stream** - repeated
  `u64 slots_scanned` records (cumulative bitmap-walk index, relative to the session's
  `slot_count` from the create plan; throttled to <=256 records, evenly spaced) terminated
  by an 8-byte `0xFFFFFFFFFFFFFFFF` sentinel - then the `u64 new_survivor_count`, then
  `CMD_SUCCESS`. A snapshot session narrows the bitmap and streams real progress records;
  a list session has no progress to stream and so sends an **immediate sentinel (zero
  records)** before the count. The empty case for a snapshot (value-width mismatch) also
  sends the sentinel with zero records. Because the wire shape is identical either way,
  the client parses any resident narrow without knowing the session mode - which matters
  because once a snapshot's survivors get sparse the server transparently materialises it
  into a compact record list, flipping the session to list mode mid-stream.

##### `CMD_PROC_TURBOSCAN_GET = 0xBDAACC13` (`proc_turboscan_get_handle`) - **requires auth bit 1**
Fetch a window of the server-resident survivor set with live current values, plus the
stored last-scan (`previous`) value and - when the session retained it - the first-scan
(`first`) value.
- **Request body:** `struct cmd_proc_turboscan_get_packet` (12 bytes):
  `{ u32 start_index; u32 count; u32 flags; }`.
- **Response:** `CMD_SUCCESS`, then `u32 hdr`, then `(hdr & 0x7FFFFFFF)` records, then
  `CMD_SUCCESS`. The header's low 31 bits are `actual_count` (`<= count`); **bit 31** flags
  the 3-value record shape so the client picks the stride before reading:
    - **bit 31 clear:** `{ u64 addr; value current; value previous }` - `8 + 2*value_length`.
    - **bit 31 set:**   `{ u64 addr; value current; value previous; value first }` - `8 + 3*value_length`.

  `current` is the **matched** value - the value the most recent scan read/matched (the
  session value store), **not** a live re-read - so it agrees with the scan and matches every
  other scan path (the client gets live values via its Refresh); `previous` is the **prior-scan**
  value (the value at the scan before the most recent one) when the session was started with
  `TS_SNAPSHOT_KEEP_PREVIOUS`,
  otherwise the last-matched value (~= `current`, the legacy default); `first` is the value
  at snapshot create and is present (bit 31 set) **only** for a session started with
  `TS_SNAPSHOT_KEEP_FIRST` whose first store was created successfully (it degrades to the
  2-value shape otherwise). The shape is uniform across single-range,
  multi-segment, list-mode and snapshot-mode sessions. `valueType` / `value_length` come
  from the session, not the request.

##### `CMD_PROC_TURBOSCAN_END = 0xBDAACC14` (`proc_turboscan_end_handle`) - **requires auth bit 1**
Free this connection's server-resident / snapshot session (also freed
automatically on disconnect).
- **Request body:** none.
- **Response:** `CMD_SUCCESS`.

##### `CMD_PROC_TURBOSCAN_CONFIG = 0xBDAACC15` (`proc_turboscan_config_handle`) - **requires auth bit 1**
Tune the snapshot value-store backing for subsequent snapshot scans (advertised via
`TSE_SNAPSHOT_CONFIG`). Lets the client trade RAM for speed and choose where a too-large
snapshot spills. Settings are global (snapshots run on a single connection) and apply to
the next `CC11 + TS_SNAPSHOT` create.
- **Request body:** `struct cmd_proc_turboscan_config_packet` (8 bytes):
  `{ u32 ram_thresh_mb; u32 spill_path_len; }`, then `spill_path_len` bytes of a spill
  **directory** path (no NUL, `<= 63` bytes).
- **Semantics:**
  - `ram_thresh_mb` - how much of the value store is **fully committed to RAM** (anon
    `mmap`). `0` resets to the **512 MiB** default. The cap is now a RAM-cache size, not an
    all-or-nothing switch:
    - store `<=` cap -> **pure anon RAM** (committed up front, fastest).
    - store `>` cap -> **hybrid**: the first `cap` bytes (whole slots) are cached in anon
      RAM and only the overflow spills to the file; the kernel page cache may keep
      additional spill pages warm opportunistically, so RAM caching is no longer
      all-or-nothing and a too-large scan never goes 100% to disk.

    Raising it commits more of the console's shared memory while a game runs (a client-
    chosen tradeoff); if the RAM commit/cache fails, the server degrades safely to the
    pure-file path. (File-backed `mmap` is **not** used - faulting a `MAP_SHARED` file page
    sleeps under a held VM lock and panics PS5 - so the spill is explicit `pread`/`pwrite`.)
  - spill directory - where the spill file (`ps5dbg_snap_NN.bin`) is written when it
    doesn't fit in RAM. Empty resets to `/data`. The internal user partition (`/data`,
    `/user`) is encrypted and can be slow (HW-measured ~35-240 MB/s depending on console
    state); an extended NVMe (`/mnt/ext1`) or USB (`/mnt/usb0`) is typically faster
    (~240 / ~550 MB/s) when present. The spill write itself uses 16 MiB chunks.
- **Response:** `CMD_SUCCESS` (or `CMD_DATA_NULL` on a malformed body / `spill_path_len > 63`).

##### `0xBDAACC16` - region classify (`proc_turboscan_regions_handle`) - **requires auth bit 1**
Enumerate every **readable** region of the target with its cache attribute and a
**measured** read throughput, so the client can offer the user a per-region "exclude
uncached/slow" choice (e.g. the PS5 GPU/Garlic blob: a large region that is uncached
and reads ~40 MB/s, usually not worth scanning - but **the server never drops anything**,
exclusion is the client's opt-in, user-overridable decision; the default is to scan
everything). The opcode is deliberately a raw literal (no `CMD_*` macro) so the published
`CMD_*` set that some clients enumerate stays unchanged.
- **Request body:** `struct cmd_proc_turboscan_regions_packet` (16 bytes):
  `{ u32 pid; u32 max; u32 probe_bytes; u32 reserved; }`.
  - `max` - cap on regions returned (`0` => server default 1024; hard cap 8192).
  - `probe_bytes` - bytes probe-read per region to time the MB/s measure (`0` => 64 KiB;
    capped at 1 MiB). The measure is **always** taken (one `proc_read_mem` per region).
- **Response:** `CMD_SUCCESS`, then `u32 count`, then `count` x
  `struct cmd_proc_turboscan_region_info` (32 bytes each), then `CMD_SUCCESS`.
  Each record: `{ u64 start; u64 end; u32 prot; u32 flags; u32 mbps; u32 reserved; }`
  where `flags` bit0 = leaf-PTE `PCD=1` (uncached) and `mbps` is the measured whole-MB/s
  read throughput of the region. Read-only; no aliasing / PTE writes.

##### `0xBDAACC17` - cancel (`proc_turboscan_cancel_handle`) - **requires auth bit 1**
Abort an in-flight turbo scan (`START` or `COUNT`) for a given pid. The command dispatcher
is serial per connection, so the connection running the long scan is busy streaming and
cannot receive a command - **CANCEL must be sent on a second, separately authed
connection**. It arms a pid-scoped flag the scan loops poll (all parallel workers observe
it), so they stop early and emit their normal terminator; the waiting client on the first
connection then unblocks. Raw literal (no `CMD_*` macro).
- **Request body:** `u32 pid` (the pid whose in-flight scan to cancel; must be non-zero).
- **Response:** `CMD_SUCCESS` (the flag is armed - it does not wait for the scan to notice).
  `CMD_DATA_NULL` if not authed / no body / `pid == 0`.
- **Effect on the cancelled scan:**
  - **Snapshot `START` (unknown-initial-value):** stops cleanly, frees the half-built
    snapshot, and returns the snapshot summary with `snapshot_ok = 0`.
  - **`START` (known-value) and `COUNT` (rescan):** stop early and return their normal
    terminator with **partial** results; the resident/snapshot session is left
    **indeterminate** - issue `END` (`0xBDAACC14`) or a fresh `START` before trusting results.
- **Staleness:** a cancel arriving before the scan starts is discarded (`START`/`COUNT`
  clear a stale same-pid flag on entry), so only a running scan can be cancelled. The
  client-driven streaming `COUNT` is already stoppable via its end sentinel and is unaffected.

##### Snapshot sub-protocol (`CC11 + TS_SNAPSHOT`, narrowed by `CC12 + TS_SERVER_RESIDENT`)
For unknown-initial-value scans. **By default the seed drops all-zero slots** (most
memory is zeroed and rarely a useful target), so `survivor_count` reflects only the
nonzero slots kept; pass `TS_SNAPSHOT_INCLUDE_ZEROS` to seed every slot instead.

**Single range vs. multi-segment.** By default the snapshot covers the single
`[address, address+length)` range from the `START` packet. With
`TS_SNAPSHOT_SEGMENTS` set (server must advertise `TSE_SNAPSHOT_SEGMENTS`), the
snapshot instead covers a client-supplied list of disjoint segments in **one**
resident session: right after the value/mask trailing data (and before the plan),
the client streams `u32 segment_count`, then `segment_count` x
`struct cmd_proc_turboscan_snap_segment` (12 bytes: `{ u64 address; u32 length; }`).
The packet's `address`/`length` are ignored in this mode. The slot space is the
concatenation of the segments, so unmapped gaps between them are never read and
storage scales with the selected bytes, not the bounding span - this is the correct
way to scan a scattered module/section selection (the alternative, spanning
`[minStart, maxEnd)` as one range, reads and stores the gaps too). Survivor
addresses are absolute, so `slot_count`/progress, `CC12` narrow, `CC13` GET, and
materialize are all unaffected by the segmentation. `segment_count` must be in
`1 .. 1048576` (an overflow guard, far beyond any real layout); outside that, or on
a server-side allocation failure, the server replies `snapshot_ok = 0` and the
client falls back to its own path.

After the two leading `CMD_SUCCESS` acks (and the segment list when
`TS_SNAPSHOT_SEGMENTS` is set), `CC11 + TS_SNAPSHOT` streams:
1. `struct cmd_proc_turboscan_snap_plan` (16 bytes): `{ u64 slot_count; u64 total_bytes; }`
   (`total_bytes` = sum of the segment lengths in multi-segment mode).
2. progress: repeated `u64 bytes_done` records, terminated by an 8-byte
   `0xFFFFFFFFFFFFFFFF`.
3. `struct cmd_proc_turboscan_snap_summary` (12 bytes):
   `{ u32 snapshot_ok; u64 survivor_count; }` - `snapshot_ok = 0` means
   ENOSPC / too large, and the client falls back to its own unknown-value path.
4. a final `CMD_SUCCESS`.

Subsequent narrowing uses `CC12 + TS_SERVER_RESIDENT` (rescans the snapshot in
place, since-last-scan) - which streams its own throttled `u64 slots_scanned` progress
records (relative to `slot_count`), terminated by the same sentinel, before the survivor
count (see CC12 above; the reply shape is mode-independent, so once the survivors get
sparse and the session materialises into a list, later narrows still parse identically) -
and `CC13 GET` fetches survivors. The value snapshot is **RAM-backed when it fits under
the RAM threshold** (default 512 MiB, tunable via `CC15`); a larger store is **hybrid** -
the first threshold bytes (whole slots) stay in anon RAM and only the overflow goes to a
`ps5dbg_snap_NN.bin` file under the spill directory (default `/data`, also `CC15`-tunable
to e.g. `/mnt/ext1` or `/mnt/usb0`). The spill is accessed by windowed `pread`/`pwrite`
**written in 16 MiB chunks** (amortizes the per-`write()` FS overhead - HW-measured ~1.5x
over 1 MiB); file-backed `mmap` is avoided because faulting a `MAP_SHARED` page sleeps
under a held VM lock and panics the console. The store is read/written sequentially, so
at most one create-chunk / narrow-window straddles the RAM/file boundary (split
transparently), and the membership bitmap is always RAM. The file is unlinked on `END` / disconnect / new scan,
and `/data` is swept at startup (spill files left on a removable/expansion mount are not
swept, but are bounded to one per client slot and truncated on reuse).

For the `valueType` / `compareType` values, see 7.

---

### 2.3 Debug commands - dispatched by `debug_handle` (`debug.c:1594-1619`)

Most handlers check `g_debug_attached` (and a non-zero pid) themselves and reply
`CMD_ERROR` if no session is active (`CMD_DEBUG_PROCESS_STOP` is the exception -
it works without a session). An unknown debug opcode replies `CMD_ERROR`. The
dispatcher does not silently drop.

#### `CMD_DEBUG_ATTACH = 0xBDBB0001` (`debug.c:549`, `debug_attach_handle`)
This is the real attach handler (there is no stub / `_svc` variant).
- **Request body:** `struct cmd_debug_attach_packet` (**4 bytes**, `{ uint32_t pid; }`).
  The client's IP comes from the connection slot recorded in 1.5, not from the
  packet.
- **Side effects:** elevates, `ptrace(PT_ATTACH)`s the target, resumes the app,
  and opens the outbound interrupt connection to the client on port 755 (1.9).
- **Response:** `CMD_SUCCESS`, or `CMD_ALREADY_DEBUG` / `CMD_DATA_NULL` /
  `CMD_ERROR`.

#### `CMD_DEBUG_DETACH = 0xBDBB0002` (`debug.c:609`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`. Runs `debug_full_teardown` (clears breakpoints /
  watchpoints, resumes, detaches, closes the 755 connection).

#### `CMD_DEBUG_SET_BREAKPOINT = 0xBDBB0003` (`debug.c:618`)
- **Request body:** `struct cmd_debug_breakpt_packet` (16 bytes, `{ index, enabled, address }`).
- **Response:** `CMD_SUCCESS`, or `CMD_INVALID_INDEX` if `index > 29`.
- **Backend:** software breakpoint - writes `0xCC` via `proc_write_mem` (which
  uses the DMAP path on FW >= 8.40), saving the original byte.
  `MAX_BREAKPOINTS = 30` (`protocol.h:273`). (The CheaterNG client caps its own
  index at 10.)

#### `CMD_DEBUG_SET_WATCHPOINT = 0xBDBB0004` (`debug.c:676`)
- **Request body:** `struct cmd_debug_watchpt_packet` (24 bytes):
  `{ index, enabled, length, breaktype, address }`.
- **Response:** `CMD_SUCCESS`, or `CMD_INVALID_INDEX` if `index > 3`.
- **Backend:** hardware breakpoint via DR0-DR3 / DR7 (written through the kernel
  dbreg path on firmwares that need it). `MAX_WATCHPOINTS = 4` (`protocol.h:274`).
  `breaktype` and `length` use the x86 DR7 encodings in 7.3.

#### `CMD_DEBUG_GET_THREAD_LIST = 0xBDBB0005` (`debug.c:769`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`, `uint32_t num`, then `num` x `uint32_t lwpid`.

#### `CMD_DEBUG_SUSPEND_THREAD = 0xBDBB0006` (`debug.c:809`)
- **Request body:** `struct cmd_debug_stopthr_packet` (4 bytes, `lwpid`).
- **Response:** `CMD_SUCCESS` or `CMD_ERROR` (`PT_SUSPEND`).

#### `CMD_DEBUG_RESUME_THREAD = 0xBDBB0007` (`debug.c:822`)
- **Request body:** `struct cmd_debug_resumethr_packet` (4 bytes, `lwpid`).
- **Response:** `CMD_SUCCESS` or `CMD_ERROR` (`PT_RESUME`).

#### `CMD_DEBUG_GETREGS = 0xBDBB0008` (`debug.c:835`)
- **Request body:** `{ uint32_t lwpid; }` (4 bytes).
- **Response:** `CMD_SUCCESS`, then a **176-byte** GP-register blob (FreeBSD
  amd64 `struct reg`).

#### `CMD_DEBUG_SETREGS = 0xBDBB0009` (`debug.c:855`)
- **Request body:** `struct cmd_debug_setregs_packet` (8 bytes, `{ lwpid, length }`).
- **Response:** `CMD_SUCCESS` (ack), reads `length` bytes (must be 176), then
  `CMD_SUCCESS`. **Two** status words.

#### `CMD_DEBUG_GETFPREGS = 0xBDBB000A` (`debug.c:876`)
- **Request body:** `{ uint32_t lwpid; }` (4 bytes).
- **Response:** `CMD_SUCCESS`, then an **832-byte** FPU/YMM blob.
- The handler reads the thread's full xsave image from the kernel
  (`kern_get_fpregs`, the thread's `pcb_save` area) so the **YMM (AVX) upper
  halves are populated**, not just the 512-byte FXSAVE/XMM legacy region.
  If the kernel path is unavailable it falls back to `PT_GETFPREGS`, which
  fills only the first 512 bytes and leaves the YMM tail zero.

#### `CMD_DEBUG_SETFPREGS = 0xBDBB000B` (`debug.c:901`)
- **Request body:** `{ uint32_t lwpid; uint32_t length; }` (8 bytes).
- **Response:** `CMD_SUCCESS` (ack), reads `length` bytes (832), then
  `CMD_SUCCESS`. **Two** status words.
- A full **832-byte** image is written back to the kernel xsave area
  (`kern_set_fpregs`), so **YMM (AVX) state is applied**. A client must send a
  complete xsave image (typically round-tripped from `GETFPREGS`) so the
  xstate header stays valid. A legacy **512-byte** blob is applied via
  `PT_SETFPREGS` instead (FXSAVE only), leaving YMM untouched.

#### `CMD_DEBUG_GETFSGSBASE = 0xBDBB000E` (`debug.c:997`)
- **Request body:** `{ uint32_t lwpid; }` (4 bytes).
- **Response:** `CMD_SUCCESS`, then a **16-byte** blob
  `{ uint64_t fs_base; uint64_t gs_base }`.
- The 64-bit FS/GS segment **base** addresses (TLS / per-thread pointers).
  These are not part of `struct reg` (`GETREGS` carries only the 16-bit
  selectors), so they are read from the thread's `pcb` via the kernel R/W
  primitive. **Kernel-path only** - no ptrace fallback; returns `CMD_ERROR`
  if the thread cannot be resolved.

#### `CMD_DEBUG_SETFSGSBASE = 0xBDBB000F` (`debug.c:1019`)
- **Request body:** `{ uint32_t lwpid; uint32_t length; }` (8 bytes).
- **Response:** `CMD_SUCCESS` (ack), reads `length` bytes (must be **16**),
  then `CMD_SUCCESS`. **Two** status words. Writes `fs_base`/`gs_base` into
  the thread's `pcb`; takes effect when the stopped thread is resumed.

#### `CMD_DEBUG_GETDBREGS = 0xBDBB000C` (`debug.c:932`)
- **Request body:** `{ uint32_t lwpid; }` (4 bytes).
- **Response:** `CMD_SUCCESS`, then a **128-byte** debug-register blob.

#### `CMD_DEBUG_SETDBREGS = 0xBDBB000D` (`debug.c:969`)
- **Request body:** `{ uint32_t lwpid; uint32_t length; }` (8 bytes).
- **Response:** `CMD_SUCCESS` (ack), reads `length` bytes (128), then
  `CMD_SUCCESS`. **Two** status words.

#### `CMD_DEBUG_CONTINUE = 0xBDBB0010` (`debug.c:1042`)
- **Request body:** `struct cmd_debug_stopgo_packet` (4 bytes); the first byte is
  the action.
- `0` -> resume; `1` -> stop (`SIGSTOP`); `2` -> kill (`SIGKILL`) - routed
  through `debug_stopgo_handle`. (Client name: `CMD_DEBUG_STOPGO`.)
- **Response:** `CMD_SUCCESS`.

#### `CMD_DEBUG_THREAD_INFO = 0xBDBB0011` (`debug.c:1087`)
- **Request body:** `struct cmd_debug_thrinfo_packet` (4 bytes, `lwpid`).
- **Response:** `CMD_SUCCESS`, `struct dbg_thrinfo_response` (40 bytes,
  `{ uint32_t lwpid; uint32_t priority; char tdname[32]; }`).

#### `CMD_DEBUG_STEP = 0xBDBB0012` (`debug.c:1115`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`. `PT_STEP` on the whole process. (Client name:
  `CMD_DEBUG_SINGLESTEP`.)

#### `CMD_DEBUG_STEP_THREAD = 0xBDBB0013` (`debug.c:1131`)
- **Request body:** `struct cmd_debug_stopthr_packet` (4 bytes, `lwpid`).
- **Response:** `CMD_SUCCESS` or `CMD_ERROR`. `PT_STEP` on a single LWP.
  (Server-only; not invoked by the CheaterNG client.)

#### `CMD_DEBUG_PROCESS_STOP = 0xBDBB0500` (`debug.c:531`)
- **Request body:** 5 raw bytes: `uint32_t pid; uint8_t state;`. Returns
  `CMD_ERROR` if `state > 2` or `pid == 0`. (Client name: `CMD_DEBUG_EXT`.)
- **Response:** `CMD_SUCCESS`, `CMD_DATA_NULL`, or `CMD_ERROR`.
- **Behaviour** (`debug.c` `debug_stopgo_handle`): if a session is active, a
  signal is staged for the next event dispatch (`0` -> deferred resume,
  `1` -> `SIGSTOP` (17), `2` -> `SIGKILL` (9)). Otherwise `kill(pid, sig)` is
  called directly using the table `{ 19 = SIGCONT (resume), 17 = SIGSTOP, 9 = SIGKILL }`.

---

### 2.4 Kernel R/W commands - dispatched by `kern_handle` (`kern.c:53-60`)

#### `CMD_KERN_BASE = 0xBDCC0001` (`kern.c:8`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`, then `uint64_t` = the kernel `.data` base
  (`KERNEL_ADDRESS_DATA_BASE`).

#### `CMD_KERN_READ = 0xBDCC0002` (`kern.c:16`)
- **Request body:** `struct cmd_kern_read_packet` (12 bytes, `{ address, length }`).
- **Response:** `CMD_SUCCESS`, then `length` bytes (`kernel_copyout_fast`).

#### `CMD_KERN_WRITE = 0xBDCC0003` (`kern.c:34`)
- **Request body:** `struct cmd_kern_write_packet` (12 bytes, `{ address, length }`).
- **Response:** `CMD_SUCCESS` (before the data phase), reads `length` bytes,
  `kernel_copyin_fast`, then `CMD_SUCCESS` again. **Two** status words.

---

### 2.5 Console commands - dispatched by `console_handle` (`console.c:312-322`)

#### `CMD_CONSOLE_REBOOT = 0xBDDD0001` (`console.c:30`)
- **Request body:** none.
- **Behaviour:** calls `sceKernelReboot()` and returns; the console reboots.

#### `CMD_CONSOLE_END = 0xBDDD0002` (`console.c:36`, `console_end_handle`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`.

#### `CMD_CONSOLE_PRINT = 0xBDDD0003` (`console.c:42`)
- **Request body:** `struct cmd_console_print_packet` `{ uint32_t length; }` (4 bytes).
- **Trailing data:** `length` bytes of text.
- **Response:** `CMD_SUCCESS`. (Writes via `klog_puts`.)

#### `CMD_CONSOLE_NOTIFY = 0xBDDD0004` (`console.c:61`)
- **Request body:** `struct cmd_console_notify_packet` `{ uint32_t messageType; uint32_t length; }` (8 bytes).
- **Trailing data:** `length` bytes of text (the client appends a trailing `\0`).
- **Response:** `CMD_SUCCESS`.
- **Behaviour:** calls `sceKernelSendNotificationRequest` with the text.
  `messageType` is read off the wire but **not used** by this handler.

#### `CMD_CONSOLE_INFO = 0xBDDD0005` (`console.c:88`, `console_info_handle`)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`. No side effect (ping variant).

#### `0xBDDD0006` - foreground-app metadata (`console.c:183`, `console_foreground_app_handle`)
Raw literal, no `CMD_*` macro. (Client name: `CMD_CONSOLE_FOREGROUND_APP`.)
- **Request body:** none.
- **Response:** `CMD_SUCCESS`, `struct cmd_console_foreground_app_response`
  (**140 bytes**, `console.c:144`):
  ```
  u32  pid;
  char titleid[16];
  char contentid[64];
  char name[40];
  char app_ver[16];     // version string (app_ver at byte offset 124)
  ```
- **Behaviour:** the foreground `eboot.bin` process is found by walking
  `allproc`. `titleid`/`contentid` are resolved by pattern-scanning the proc
  struct (FW-agnostic), falling back to per-firmware offsets. The version is read
  from the title's `param.sfo` (`APP_VER` / `VERSION`, the lexically larger of
  the two), falling back to `param.json` (`contentVersion` /
  `originContentVersion`, else `masterVersion`). If there is no foreground game
  all fields are zeroed (`pid == 0`).

---

## 3. In-process kernel/target primitives

ps5debug-NG runs the entire wire-protocol server inside SceShellCore (the
installer injects the embedded debugger ELF as a SceShellCore-internal thread).
"Kernel-side" operations are performed from userland using primitives from
[ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) plus short kernel
patches applied at install time:

| Concern                              | How ps5debug-NG implements it                                              |
|--------------------------------------|----------------------------------------------------------------------------|
| Process enumeration (`CMD_PROC_LIST`)| Walk the kernel `allproc` linked list with `kernel_copyout_fast` (`proc.c` `proc_list_handle`). |
| Target memory read                   | `sys_proc_rw_w0` (mdbg), with a DMAP page-table-walk read for Sony-aux regions (`proc.c` `proc_read_mem`). |
| Target memory write                  | DMAP page-table-walk write on FW >= 8.40 (mdbg write is `EPERM`-gated there), mdbg `sys_proc_rw_w1` otherwise (`proc.c` `proc_write_mem`). |
| `mprotect` / alloc / free / call / ELF | `sys_proc_cmd` syscall variants (`kdbg.h` `SYS_PROC_*`). |
| Kernel base / kernel R/W             | `KERNEL_ADDRESS_DATA_BASE`, `kernel_copyout_fast` / `kernel_copyin_fast` (`kern.c`). |
| VM map (`CMD_PROC_MAPS`)             | Read `vmspace` + map entries via `kernel_copyout_fast`, augmented by a page-table walk (`scan.c` `sys_proc_vm_map`, `proc_ptwalk_augment`). |
| Console reboot / notify / print      | `sceKernelReboot`, `sceKernelSendNotificationRequest`, `klog_puts`.        |

The installer's role is bootstrap-only: find SceShellCore, apply the FW-specific
kernel patch, set up the target's execution state, and hand control to the
embedded debugger. After that the installer exits and the debugger services TCP.

---

## 4. Full command ID table

Auth = requires `g_proc_auth_state & 2` (set via `CMD_PROC_AUTH`).

| Hex          | Server handler name              | File / location          | Auth? |
|--------------|----------------------------------|--------------------------|-------|
| `0xBD000001` | `handle_version`                 | `meta.c` (inline)        |       |
| `0xBD000500` | `handle_fw_version`              | `meta.c` (inline)        |       |
| `0xBD000501` | `handle_branding`                | `meta.c` (inline)        |       |
| `0xBD000502` | `handle_platform_id`             | `meta.c` (inline)        |       |
| `0xBDAACC06` | `CMD_PROC_NOP`                   | `meta.c` (inline)        |       |
| `0xBDAA0001` | `proc_list_handle`               | `proc.c`                 |       |
| `0xBDAA0002` | `proc_read_handle`               | `proc.c`                 |       |
| `0xBDAA0003` | `proc_write_handle`              | `proc.c`                 |       |
| `0xBDAA0004` | `proc_maps_handle`               | `proc.c`                 |       |
| `0xBDAA0005` | `proc_install_handle` (stub)     | `proc.c`                 |       |
| `0xBDAA0006` | `proc_call_handle`               | `proc.c`                 |       |
| `0xBDAA0007` | `proc_elf_handle`                | `proc.c`                 |       |
| `0xBDAA0008` | `proc_protect_handle`            | `proc.c`                 |       |
| `0xBDAA0009` | `proc_scan_handle`               | `scan.c`                 |       |
| `0xBDAA000A` | `proc_info_handle`               | `proc.c`                 |       |
| `0xBDAA000B` | `proc_alloc_handle`              | `proc.c`                 |       |
| `0xBDAA000C` | `proc_free_handle`               | `proc.c`                 |       |
| `0xBDAA000D` | `proc_unknown_d_handle`          | `proc.c` (raw literal)   |       |
| `0xBDAA000E` | `proc_alloc_hinted_handle`       | `proc.c`                 |       |
| `0xBDAA0010` | `proc_elf_rpc_handle`            | `proc.c`                 |       |
| `0xBDAA0020` | `proc_disasm_region_handle`      | `proc.c`                 |       |
| `0xBDAA0021` | `proc_extract_code_xrefs_handle` | `proc.c`                 |       |
| `0xBDAA0022` | `proc_find_xrefs_to_handle`      | `proc.c`                 |       |
| `0xBDAA0023` | `proc_read_stack_handle`         | `proc.c`                 |       |
| `0xBDAA0024` | `proc_assemble_handle`           | `assemble.c` (raw literal) |     |
| `0xBDAA0501` | `proc_scan_aob_handle`           | `scan.c`                 |       |
| `0xBDAA0502` | `proc_scan_aob_multi_handle`     | `scan.c`                 |       |
| `0xBDAACCFF` | `proc_auth_handle`               | `auth.c`                 |       |
| `0xBDAACC01` | `proc_scan_start_handle`         | `scan.c`                 | bit 1 |
| `0xBDAACC02` | `proc_scan_count_handle`         | `scan.c`                 | bit 1 |
| `0xBDAACC03` | `proc_scan_get_handle`           | `scan.c`                 | bit 1 |
| `0xBDAACC04` | `proc_write_multi_handle`        | `proc.c`                 |       |
| `0xBDAACC10` | `proc_turboscan_caps_handle`      | `scan_turbo.c`            |       |
| `0xBDAACC11` | `proc_turboscan_start_handle`     | `scan_turbo.c`            | bit 1 |
| `0xBDAACC12` | `proc_turboscan_count_handle`     | `scan_turbo.c`            | bit 1 |
| `0xBDAACC13` | `proc_turboscan_get_handle`       | `scan_turbo.c`            | bit 1 |
| `0xBDAACC14` | `proc_turboscan_end_handle`       | `scan_turbo.c`            | bit 1 |
| `0xBDAACC15` | `proc_turboscan_config_handle`    | `scan_turbo.c`            | bit 1 |
| `0xBDAACC16` | `proc_turboscan_regions_handle`   | `scan_turbo.c`            | bit 1 |
| `0xBDAACC17` | `proc_turboscan_cancel_handle`    | `scan_turbo.c`            | bit 1 |
| `0xBDAACC24` | `proc_arena_handle`              | `proc.c`                 |       |
| `0xBDBB0001` | `debug_attach_handle`            | `debug.c`                |       |
| `0xBDBB0002` | `debug_detach_handle`            | `debug.c`                |       |
| `0xBDBB0003` | `debug_set_breakpoint_handle`    | `debug.c`                |       |
| `0xBDBB0004` | `debug_set_watchpoint_handle`    | `debug.c`                |       |
| `0xBDBB0005` | `debug_get_thread_list_handle`   | `debug.c`                |       |
| `0xBDBB0006` | `debug_suspend_thread_handle`    | `debug.c`                |       |
| `0xBDBB0007` | `debug_resume_thread_handle`     | `debug.c`                |       |
| `0xBDBB0008` | `debug_getregs_handle`           | `debug.c`                |       |
| `0xBDBB0009` | `debug_setregs_handle`           | `debug.c`                |       |
| `0xBDBB000A` | `debug_getfpregs_handle`         | `debug.c`                |       |
| `0xBDBB000B` | `debug_setfpregs_handle`         | `debug.c`                |       |
| `0xBDBB000C` | `debug_getdbregs_handle`         | `debug.c`                |       |
| `0xBDBB000D` | `debug_setdbregs_handle`         | `debug.c`                |       |
| `0xBDBB000E` | `debug_getfsgsbase_handle`       | `debug.c`                |       |
| `0xBDBB000F` | `debug_setfsgsbase_handle`       | `debug.c`                |       |
| `0xBDBB0010` | `debug_continue_handle`          | `debug.c`                |       |
| `0xBDBB0011` | `debug_thread_info_handle`       | `debug.c`                |       |
| `0xBDBB0012` | `debug_step_handle`              | `debug.c`                |       |
| `0xBDBB0013` | `debug_step_thread_handle`       | `debug.c`                |       |
| `0xBDBB0500` | `debug_process_stop_handle`      | `debug.c`                |       |
| `0xBDCC0001` | `kern_base_handle`               | `kern.c`                 |       |
| `0xBDCC0002` | `kern_read_handle`               | `kern.c`                 |       |
| `0xBDCC0003` | `kern_write_handle`              | `kern.c`                 |       |
| `0xBDDD0001` | `console_reboot_handle`          | `console.c`              |       |
| `0xBDDD0002` | `console_end_handle`             | `console.c`              |       |
| `0xBDDD0003` | `console_print_handle`           | `console.c`              |       |
| `0xBDDD0004` | `console_notify_handle`          | `console.c`              |       |
| `0xBDDD0005` | `console_info_handle`            | `console.c`              |       |
| `0xBDDD0006` | `console_foreground_app_handle`  | `console.c` (raw literal) |      |

---

## 5. Request packet appendix

All structs are `__attribute__((packed))`; most are defined in
`common/include/protocol.h` (a few are local to their handler's `.c`).

| Struct                                  | Size | Fields                                                                    |
|-----------------------------------------|------|---------------------------------------------------------------------------|
| `cmd_packet` (wire portion)             | 12   | `u32 magic; u32 cmd; u32 datalen;`                                        |
| `cmd_proc_read_packet`                  | 16   | `u32 pid; u64 address; u32 length;`                                       |
| `cmd_proc_write_packet`                 | 16   | `u32 pid; u64 address; u32 length;`                                       |
| `cmd_proc_maps_packet`                  | 4    | `u32 pid;`                                                                |
| `cmd_proc_install_packet`               | 4    | `u32 pid;`                                                                |
| `cmd_proc_unknown_d_packet`             | 4    | `u32 pid;`                                                                |
| `cmd_proc_call_packet`                  | 68   | `u32 pid; u64 rpcstub,rpc_rip,rpc_rdi,rpc_rsi,rpc_rdx,rpc_rcx,rpc_r8,rpc_r9;` |
| `cmd_proc_elf_packet`                   | 8    | `u32 pid; u32 length;`                                                    |
| `cmd_proc_elf_rpc_packet`               | 8    | `u32 pid; u32 length;`                                                    |
| `cmd_proc_protect_packet` (in `proc.c`) | 20   | `u32 pid; u64 address; u32 length; u32 prot;`                            |
| `cmd_proc_scan_packet`                  | 10   | `u32 pid; u8 valueType, compareType; u32 lenData;`                        |
| `cmd_proc_scan_start_packet`            | 23   | `u32 pid; u64 address; u32 length; u8 valueType, compareType, alignment; u32 lenData;` |
| `cmd_proc_scan_count_packet`            | 18   | `u32 pid; u64 base_address; u8 valueType, compareType; u32 lenData;`      |
| `cmd_proc_scan_aob_packet`              | 22   | `u32 pid; u64 address; u32 length; u8 max_matches, stop_flag; u32 pattern_length;` |
| `cmd_proc_scan_aob_multi_packet`        | 21   | `u32 pid; u64 address; u32 length; u8 stop_flag; u32 patterns_length;`    |
| `cmd_proc_auth_packet`                  | 8    | `u32 magic (0xBB40E64D); u32 flags;`                                      |
| `cmd_proc_scan_get_packet`              | 8    | `u32 pid; u32 count;`                                                     |
| `cmd_proc_turboscan_start_packet`        | 27   | `u32 pid; u64 address; u32 length; u8 valueType, compareType, alignment; u32 lenData; u32 flags;` |
| `cmd_proc_turboscan_count_packet`        | 22   | `u32 pid; u64 base_address; u8 valueType, compareType; u32 lenData; u32 flags;` |
| `cmd_proc_turboscan_get_packet`          | 12   | `u32 start_index; u32 count; u32 flags;`                                  |
| `cmd_proc_info_packet`                  | 4    | `u32 pid;`                                                                |
| `cmd_proc_alloc_packet`                 | 8    | `u32 pid; u32 length;`                                                    |
| `cmd_proc_alloc_hinted_packet`          | 16   | `u32 pid; u64 hint; u32 length;`                                          |
| `cmd_proc_free_packet`                  | 16   | `u32 pid; u64 address; u32 length;`                                       |
| `cmd_proc_disasm_packet`                | 20   | `u32 pid; u64 address; u32 length; u32 max_entries;`                      |
| `cmd_proc_xrefs_to_packet`              | 24   | `u32 pid; u64 scan_address; u32 scan_length; u64 target_address;`         |
| `cmd_proc_read_stack_packet`            | 24   | `u32 pid; u64 rbp; u64 rsp; u32 depth;`                                   |
| `cmd_proc_assemble_packet`              | 12   | `u64 base_addr; u32 ks_opt_syntax;` (asm text follows in the same body)   |
| `cmd_debug_attach_packet`               | 4    | `u32 pid;`                                                                |
| `cmd_debug_breakpt_packet`              | 16   | `u32 index, enabled; u64 address;`                                        |
| `cmd_debug_watchpt_packet`              | 24   | `u32 index, enabled, length, breaktype; u64 address;`                     |
| `cmd_debug_stopthr_packet`              | 4    | `u32 lwpid;`                                                              |
| `cmd_debug_setregs_packet`              | 8    | `u32 lwpid; u32 length;`                                                  |
| `cmd_debug_stopgo_packet`               | 4    | `u32 stop;` (first byte = action 0/1/2)                                   |
| `cmd_debug_thrinfo_packet`              | 4    | `u32 lwpid;`                                                              |
| `cmd_kern_read_packet`                  | 12   | `u64 address; u32 length;`                                                |
| `cmd_kern_write_packet`                 | 12   | `u64 address; u32 length;`                                                |
| `cmd_console_print_packet` (in `console.c`)  | 4 | `u32 length;`                                                          |
| `cmd_console_notify_packet` (in `console.c`) | 8 | `u32 messageType; u32 length;`                                         |

## 6. Response packet appendix

| Struct                                  | Size | Fields                                                                    |
|-----------------------------------------|------|---------------------------------------------------------------------------|
| `proc_list_entry` (streamed)            | 36   | `char name[32]; int32_t pid;`                                            |
| `proc_vm_map_entry` (streamed)          | 58   | `char name[32]; u64 start; u64 end; u64 offset; u16 prot;`               |
| `cmd_proc_call_response`                | 12   | `u32 pid; u64 rpc_rax;`                                                   |
| `cmd_proc_turboscan_caps_response`       | 16   | `u32 version; u32 engines; u32 max_threads; u32 reserved;`               |
| `cmd_proc_turboscan_regions_packet`      | 16   | `u32 pid; u32 max; u32 probe_bytes; u32 reserved;`                       |
| `cmd_proc_turboscan_region_info` (streamed)| 32 | `u64 start; u64 end; u32 prot; u32 flags; u32 mbps; u32 reserved;`       |
| `cmd_proc_turboscan_resident_summary`    | 12   | `u32 resident_stored; u64 count;`                                        |
| `cmd_proc_turboscan_snap_plan`           | 16   | `u64 slot_count; u64 total_bytes;`                                       |
| `cmd_proc_turboscan_snap_summary`        | 12   | `u32 snapshot_ok; u64 survivor_count;`                                   |
| `cmd_proc_elf_rpc_response`             | 8    | `u64 entry;`                                                             |
| `cmd_proc_alloc_response`               | 8    | `u64 address;`                                                           |
| `cmd_proc_info_response`                | 188  | `u32 pid; char name[40], path[64], titleid[16], contentid[64];`          |
| `cmd_proc_assemble_ok`                  | 8    | `u32 byte_len; u32 insn_count;` (then `byte_len` machine bytes)           |
| `cmd_proc_assemble_err`                 | 8    | `u32 ks_errno; u32 msg_len;` (then `msg_len` chars of `ks_strerror`)     |
| `cmd_console_foreground_app_response`   | 140  | `u32 pid; char titleid[16], contentid[64], name[40], app_ver[16];`       |
| `dbg_thrinfo_response`                  | 40   | `u32 lwpid, priority; char tdname[32];`                                  |
| `disasm_instr_entry` (streamed)         | 32   | see 2.2                                                                   |
| register blobs (raw, not structs)       | 176 / 832 / 128 | GP regs / FPU+YMM / debug regs                                |

(`CMD_PROC_INTALL` returns a bare `u64 rpcstub`, which is always `0` in this build.)

---

## 7. Enum reference

The `valueType` / `compareType` / DR7 enums are **not** defined in
`protocol.h`. The server uses bare integers (`scan_compare.c`); the symbolic
names live in the client (`PS4DBG.cs`). The values below are the wire integers.

### 7.1 Scan value type (server sizes from `scan_compare.c` `proc_scan_getSizeOfValueType`)

| Value | Name               | Size |
|-------|--------------------|------|
| 0     | `valTypeUInt8`     | 1    |
| 1     | `valTypeInt8`      | 1    |
| 2     | `valTypeUInt16`    | 2    |
| 3     | `valTypeInt16`     | 2    |
| 4     | `valTypeUInt32`    | 4    |
| 5     | `valTypeInt32`     | 4    |
| 6     | `valTypeUInt64`    | 8    |
| 7     | `valTypeInt64`     | 8    |
| 8     | `valTypeFloat`     | 4    |
| 9     | `valTypeDouble`    | 8    |
| 10    | `valTypeArrBytes`  | from `lenData` (mask-driven) |
| 11    | `valTypeString`    | from `lenData` |

(The client additionally defines `valTypePointer = 12` and `valTypeNone = 13`
sentinels; the server treats any value `> 9` as size 0.)

### 7.2 Scan compare type (`scan_compare.c` `proc_scan_compareValues`, cmpType 0-12)

| Value | Name                               |
|-------|------------------------------------|
| 0     | `ExactValue`                       |
| 1     | `FuzzyValue`                       |
| 2     | `BiggerThan`                       |
| 3     | `SmallerThan`                      |
| 4     | `ValueBetween`                     |
| 5     | `IncreasedValue`                   |
| 6     | `IncreasedValueBy`                 |
| 7     | `DecreasedValue`                   |
| 8     | `DecreasedValueBy`                 |
| 9     | `ChangedValue`                     |
| 10    | `UnchangedValue`                   |
| 11    | `UnknownInitialValue`              |
| 12    | `UnknownInitialLowValue`           |

(The client additionally defines `PointerValue = 13` and `None = 14`.)

### 7.3 DR7 encoding for hardware watchpoints (`PS4DBG.cs` `WATCHPT_*`; server applies raw shifts in `debug.c`)

`breaktype` in `cmd_debug_watchpt_packet`:

| Value | Name              |
|-------|-------------------|
| 0     | `DBREG_DR7_EXEC`  |
| 1     | `DBREG_DR7_WRONLY`|
| 3     | `DBREG_DR7_RDWR`  |

`length` (reused as the DR7 length field):

| Value | Bytes |
|-------|-------|
| 0     | 1     |
| 1     | 2     |
| 2     | 8     |
| 3     | 4     |

---

## 8. Response framing patterns

Reply shapes used across handlers:

1. **Fixed status:** a single `uint32_t` status (usually `CMD_SUCCESS`). Used by
   protect, breakpoint/watchpoint management, thread suspend/resume, continue,
   step, etc.
2. **Status + fixed struct:** status then a `struct cmd_*_response` of known
   size. Used by info, call, alloc, alloc-hinted, elf-rpc, thread-info,
   foreground-app.
3. **Status + count + array:** status, `uint32_t count`, then `count` elements.
   Used by process list, VM maps, and the debug thread list.
4. **Streamed with sentinel:** status, then a sequence of records terminated by a
   sentinel. `CMD_PROC_DISASM_REGION` uses a 32-byte all-`0xFF` record;
   `CMD_PROC_EXTRACT_CODE_XREFS` / `CMD_PROC_FIND_XREFS_TO`, the legacy
   `CMD_PROC_SCAN`, and `CMD_PROC_SCAN_START` / `_COUNT` / `_GET` stream
   `uint64_t`s (or `uint64_t`-length-prefixed blocks) terminated by
   `0xFFFFFFFFFFFFFFFF`. (The two AOB scans instead return a fixed count of
   `uint64_t` results with no sentinel.)
5. **Ack + data phase + final status (two status words):** the handler sends
   `CMD_SUCCESS`, reads the trailing payload, then sends a final status. Used by
   `CMD_PROC_WRITE`, `CMD_PROC_ELF`, `CMD_PROC_ELF_RPC`, `CMD_KERN_WRITE`, and
   `CMD_DEBUG_SETREGS` / `SETFPREGS` / `SETDBREGS`. Clients must consume both
   status words.
6. **Multi-phase (scans and the auth handshake):** these interleave several
   `CMD_SUCCESS` acks with read/stream phases. The number and placement of status
   words varies per command (two to three for the legacy and AOB scans and
   `SCAN_START` / `_COUNT`; a single status for `SCAN_GET`); see each command's
   entry in 2.2 and the auth handshake in 1.8 for the exact sequence.

---

## 9. Known source-code oddities

Documented so a developer does not mistake them for bugs:

- `CMD_PROC_INTALL` is misspelled (missing `S`), preserved on the wire; the
  handler is also a stub that returns `rpcstub = 0` without injecting anything.
- Three opcodes have no `CMD_*` macro and are bare hex literals in their switch:
  `0xBDAA000D` (first-map probe), `0xBDAA0024` (assemble), `0xBDDD0006`
  (foreground app).
- Status words are bit-swapped on the wire by `net_send_int32` (1.6); payloads
  are not. The server-side `CMD_SUCCESS` macro is `0x40000000`, which is
  `0x80000000` on the wire.
- The 1184-byte debug interrupt packet (1.9) has no named struct or size macro in
  the server; it is built by hand at fixed offsets. `savefpu` lands at offset
  224, which is not 64-byte aligned (intentional).
- `g_proc_auth_state` is a single global (not per-connection) and is not reset on
  disconnect.
- The disassembler amalgamation (`third_party/zydis/Zydis.c`) is built with a
  Makefile override (`-O3 -DNDEBUG -w -DZYAN_NO_LIBC`) distinct from the rest of
  the payload.

---

*This document reflects the `ps5debug-NG v1.3.1` payload
(`common/include/version.h`; v1.3.1 added the Turbo Scan cancel command `0xBDAACC17`).
Line numbers cite the sources as of this writing
and may drift; the source under `common/include/protocol.h`,
`debugger/source/`, and `common/source/` is the authoritative reference.*
