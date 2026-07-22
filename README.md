# ps5debug-NG

A debugger payload for jailbroken PlayStation 5 consoles. Ships a userland
command server that runs inside SceShellCore, letting remote clients inspect
and manipulate running processes, the kernel itself, and the system UI over a
simple TCP protocol.

ps5debug-NG is inspired by Ctn's `ps5debug 1.0b5` and is wire-compatible with
it - existing clients should work without modification. It is licensed under
GPL-3.

Discord Server: [Team Reaper](https://discord.gg/7bjtgZf4PY)

---

## Supported firmwares

The kernel kpatch routine in [installer/source/main.c](installer/source/main.c)
recognises the following firmware families. Booting on an unsupported FW prints
`port_outer: kpatch SKIP - unsupported FW magic 0x...` to the kernel log and
aborts cleanly.

| Family | Point releases recognised                       | Status                                    |
|--------|-------------------------------------------------|-------------------------------------------|
| 3.xx   | 3.00, 3.10, 3.20, 3.21                          | Fully Verified                            |
| 4.xx   | 4.00, 4.02, 4.03, 4.50, 4.51                    | Fully Verified                            |
| 5.xx   | 5.00, 5.02, 5.10, 5.50                          | Fully Verified                            |
| 6.xx   | 6.00, 6.02, 6.50                                | Fully Verified                            |
| 7.xx   | 7.00, 7.01, 7.01.01, 7.20, 7.40, 7.60, 7.61     | Fully Verified                            |
| 8.xx   | 8.00, 8.20, 8.40, 8.60                          | Fully Verified                            |
| 9.xx   | 9.00, 9.05, 9.20, 9.40, 9.60                    | Fully Verified                            |
| 10.xx  | 10.00, 10.01, 10.20, 10.40, 10.60               | Fully Verified                            |
| 11.xx  | 11.00, 11.20, 11.40, 11.60                      | Fully Verified                            |
| 12.xx  | 12.00, 12.02, 12.20, 12.40, 12.60, 12.70        | Fully Verified                            |
| 13.xx  | 13.00, 13.20                                    | Fully Verified                            |

The point releases above are the exact FW magic values recognised by the switch
in [installer/source/main.c](installer/source/main.c); that file is the source
of truth. Clients can read the running FW with `CMD_FW_VERSION`, which returns
the firmware as a decimal `uint16_t` (e.g. `900` for 9.00, `1240` for 12.40).

---

## Primary Features

### Process inspection and manipulation
- **Enumerate processes** (process name + pid list).
- **Read and write target memory** in streamed chunks.
- **List virtual memory maps** - ranges, protections, backing names.
- **Query process metadata** - name, path, titleId, contentId.
- **Identify the foreground app** (`0xBDDD0006`) - returns pid + titleid +
  contentid + process name + the game's version, parsed server-side from the
  title's `param.sfo`. Useful for clients that need to know what's currently
  running without listing every process.
- **Server-side stack walk** (`CMD_PROC_READ_STACK`) - the server walks the
  RBP chain itself (up to 64 frames) and bundles each frame's saved-RBP,
  return address, frame-local bytes, and a 200-byte code window around the
  return address into one response. Clients avoid paying many TCP round-trips
  per stack frame.
- **Change memory protection** on arbitrary target regions.
- **Allocate / free / hint-allocate** memory inside any target process. Plain
  allocations are served from a server-side **per-pid arena** (one hijack per 16 MB
  segment, then zero-hijack sub-allocation) so heavy concurrent allocation no longer
  trips the thread-hijack crash; transparent to clients, toggleable via `0xBDAACC24`.

### In-target code execution
- **Call arbitrary functions** with up to six SysV ABI register arguments and
  read back `rax` (`CMD_PROC_CALL`) - serviced kernel-side via `sys_proc_cmd`.
- **Install an RPC stub** (`CMD_PROC_INTALL`, opcode `0xBDAA0005`; note the
  source spelling). In the current build this handler is a stub that returns a
  `0` handle and performs no injection.
- **Load ELFs** into a target process - either jump to the entry point
  immediately (`CMD_PROC_ELF`) or return the entry for later invocation
  (`CMD_PROC_ELF_RPC`).

### Full userland debugger
- **Attach** to a single target with `CMD_DEBUG_ATTACH` (sets up an async
  interrupt channel back to the client).
- **Software breakpoints** - up to **30** slots, transparent `0xCC` injection.
- **Hardware watchpoints** - up to **4** DR0-DR3 slots with read / write /
  read-write and 1/2/4/8-byte granularity.
- **Thread control** - list, suspend, resume, single-step, per-thread step.
- **Full register access** - general-purpose, FPU + YMM (AVX), debug registers,
  and the FS/GS segment base addresses (TLS pointers).
- **Continue / stop / halt** the whole process from one command.
- **Asynchronous interrupt packets** delivered on a separate TCP connection so
  the client never polls.

### Kernel access
- Get the **kernel base address**.
- **Read** arbitrary kernel memory.
- **Write** arbitrary kernel memory.

### Built-in Zydis disassembler
Large memory regions never leave the PS5. Three server-side decoder commands
keep bandwidth low:
- `CMD_PROC_DISASM_REGION` - packed 32-byte-per-instruction stream with
  control-flow, memory-operand, and RIP-relative metadata.
- `CMD_PROC_EXTRACT_CODE_XREFS` - all resolved RIP-relative operand targets in
  a region, streamed (not deduplicated server-side).
- `CMD_PROC_FIND_XREFS_TO` - only instructions whose RIP-relative target equals
  a specific address.

### Built-in Keystone assembler (x86-64)
A cross-compiled LLVM-MC Keystone (x86-only, no exceptions / no RTTI, static
~4 MB) is embedded in the payload, exposed via the raw-literal opcode
`0xBDAA0024`. Lets clients assemble asm text into machine code on the console
itself.
- Pure userspace - needs no attached process and no `CMD_PROC_AUTH` handshake.
- Request: `u64 base_addr; u32 ks_opt_syntax;` + asm text (NUL not required).
  `ks_opt_syntax` defaults to Intel; pass 1/2/4/8/0x10 for Intel/ATT/NASM/MASM/GAS.
- Response: `CMD_SUCCESS` + `u32 byte_len; u32 insn_count;` + machine bytes,
  or `CMD_ERROR` + `u32 ks_errno; u32 msg_len;` + Keystone's human-readable error.
- The opcode is deliberately a raw literal (no `CMD_*` macro) so the published
  `CMD_*` set that some clients enumerate stays unchanged.

### Memory scanning
- **Value scan** (`CMD_PROC_SCAN`) - single-pass, 12 value types × 13 compare
  modes (exact, fuzzy, bigger/smaller, between, increased, decreased, changed,
  etc.).
- **Iterative scan** (`SCAN_START` → `SCAN_COUNT` → `SCAN_GET`) - narrows a
  result set over many passes. The client holds the candidate list and streams
  it back each pass; the server re-reads memory and re-compares.
- **AOB scan** (`CMD_PROC_SCAN_AOB`) - byte patterns with a per-byte wildcard
  mask.
- **Multi-pattern AOB scan** (`CMD_PROC_SCAN_AOB_MULTI`) - many patterns in
  one pass.
- **Auth-gated** - only the iterative scan trio (`SCAN_START` / `SCAN_COUNT` /
  `SCAN_GET`) requires a prior `CMD_PROC_AUTH` handshake; the value scan and the
  AOB scans do not.

### Turbo scan family (v1.3.0, additive + capability-gated)
A faster, opt-in scan path (`CMD_PROC_TURBOSCAN_*`, `0xBDAACC10`-`0xBDAACC17`) that
runs alongside the legacy and iterative scanners, which are byte-for-byte
unchanged. A client detects it via `CMD_PROC_TURBOSCAN_CAPS` and falls back to the
iterative trio when it (or a specific engine) is absent. Result format mirrors the
iterative scan, so clients reuse one parser.
- **SIMD comparator** - typed AVX2 (256-bit) exact-match inner loop, ~25-32x the
  per-element compare of the legacy path (`TSE_SIMD_COMPARE`).
- **Server-resident result sets** (`TSE_SERVER_RESIDENT`) - the survivor set can
  live in a per-connection server buffer instead of being re-uploaded each pass;
  rescans refresh each survivor's baseline so "since last scan" deltas work without
  the client holding state. `CMD_PROC_TURBOSCAN_GET` fetches values on demand.
- **Unknown-initial-value scans** (`TSE_SNAPSHOT`) - a server-side value snapshot
  (RAM, or an NVMe `/data` file for large regions) drives
  increased/decreased/changed narrowing with no known starting value, materialising
  to a compact record list once survivors get sparse. Dense snapshots use a bitmap;
  Simple float snapshots use survivor records from the start. By default the seed **drops
  all-zero slots** (most memory is zeroed and rarely useful); `TS_SNAPSHOT_INCLUDE_ZEROS`
  keeps them.
- **Multi-segment scans** (`TSE_SNAPSHOT_SEGMENTS`) - a single session can cover a
  list of disjoint regions (`TS_SNAPSHOT_SEGMENTS` + a trailing segment list) instead
  of one contiguous range, for both an unknown-value snapshot (`TS_SNAPSHOT`) and a
  known-value server-resident scan (`TS_SERVER_RESIDENT`). The slot/record space spans
  only the mapped segments, so unmapped gaps between selected modules/sections are never
  read and storage scales with the selected bytes - letting a scattered selection use
  the turbo server-side path instead of falling back to per-section streaming. (When a
  segmented resident scan overflows the server buffer it declines with an empty result
  stream and the client streams per-section itself.)
- **Snapshot storage tuning** (`TSE_SNAPSHOT_CONFIG`, `CMD_PROC_TURBOSCAN_CONFIG`) - the
  client can set the **RAM threshold** (how large the value store may be before it spills
  to disk; default 512 MiB) and the **spill directory** (default `/data`; the encrypted
  internal partition can be slow, so an extended NVMe `/mnt/ext1` or USB `/mnt/usb0` is
  often much faster). Spill writes use 16 MiB chunks.
- **Aliasing read engine** (`TSE_ALIASING`, opt-in, default off) - maps the
  target's physical pages into the server's address space via guarded page-table
  writes so the scan reads in place at DRAM bandwidth instead of copying.
  Layout-agnostic (4K / 2MB / 1GB pages); enabled per request with
  `TS_USE_ALIASING`, and always falls back to the normal read path on any
  guard/verify miss (mdbg is the floor).
- **Parallel compare** (`TSE_PARALLEL_COMPARE`, opt-in, default off) - with
  `TS_PARALLEL_COMPARE` on an aliased exact-match streaming scan, the server splits
  the scan across worker threads. This is for **single-connection** clients: a
  multi-connection client parallelizes better by opening more connections (the server
  threads per connection) and should leave this clear. Don't set both - they
  over-subscribe. Same wire result either way.
- **Rescan aliasing** (`TSE_RESCAN_ALIASING`, opt-in, default off) - with
  `TS_RESCAN_ALIASING` on a `COUNT` rescan, full-size (gap-bridged, contiguous)
  survivor windows read via the aliasing engine instead of mdbg (~2-3x on
  dense/moderate-density rescans; the win grows as survivors stay dense). Tiny
  scattered windows and any alias miss stay on mdbg. The survivor set is
  per-connection, so it is single-connection by nature; a multi-connection client
  must not enable it across many connections at once. Same wire result either way.
- **Float policy offload** (`TSE_FLOAT_POLICY`, `TSE_COMPACT_SIMPLE_SNAPSHOT`) - clients may send
  `TS_FLOAT_SIMPLE` plus the configured exponent-distance threshold so the server
  excludes extreme/denormal float and double candidates from survivor membership,
  later narrowing, and streaming/GET transfer. `TS_FLOAT_EXACT` makes exact-value
  float/double scans use numeric IEEE equality instead of the legacy fuzzy
  comparison. The policy is enforced consistently during streaming START,
  snapshot creation, and every resident or client-driven COUNT rescan. When Simple
  seeds a snapshot, filtering now happens before storage: only survivor records are
  written, no raw-slot bitmap is allocated, optional First/Previous values are embedded
  per record, and each later narrow compacts the stream again. The dedicated compact
  capability bit lets clients distinguish this storage guarantee from older payloads
  that advertised float-policy correctness but still used dense snapshot backing.
- **Region classify** (`0xBDAACC16`) - returns every readable region with its cache
  attribute (uncached `PCD` leaf-PTE bit) and a measured read throughput, so the client
  can offer the user a per-region "exclude uncached/slow" choice (e.g. the GPU/Garlic
  blob, which reads ~40 MB/s and is rarely worth scanning). The server never drops
  anything - exclusion is the client's opt-in, user-overridable decision, default scan
  everything. The opcode is a raw literal (no `CMD_*` macro) so the enumerated `CMD_*`
  set stays unchanged.
- **Cancel** (`0xBDAACC17`, v1.3.1) - abort a long scan mid-flight (e.g. an unknown-value
  snapshot over a huge region). Sent from a second connection, since the scanning
  connection is busy streaming; a cancelled snapshot create returns `snapshot_ok=0`.
- **Auth-gated** - `TURBOSCAN_START` / `_COUNT` / `_GET` / `_END` / `_CANCEL` require the
  `CMD_PROC_AUTH` handshake (like the iterative trio); `TURBOSCAN_CAPS` does not.

### System UI integration
- **Push notifications** to the user's screen with arbitrary UTF-8 text.
- **Print** to the kernel console.
- **Reboot** the console.

### Klog forwarder
- TCP **3232** streams the kernel log to a connected client (host-side
  `klog reader` style). Survives suspend/resume the same as the main server.

### Discovery
- A UDP broadcast responder on port `1010` echoes a handshake magic
  (`0xFFFFAAAA`) so clients can find the PS5 on the LAN without hard-coding
  an IP.

### Rest-mode support
- The payload **survives suspend / resume** without needing to be reloaded.
  A supervisory loop polls the network periodically: when the console drops
  into rest mode the server exits cleanly, and as soon as the network comes
  back the server restarts and a fresh "online" notification fires.
- Clients see a clean disconnect on port 744 when rest mode begins and can
  simply reconnect after wake.

### Performance-oriented design
- Non-blocking sockets with `TCP_NODELAY`, `SO_KEEPALIVE`, large transfer
  chunks.
- Zydis amalgamation compiled at `-O3 -DNDEBUG` for maximum decode throughput.
- Link-time dead stripping (`-ffunction-sections -fdata-sections
  -Wl,--gc-sections`).
- Interrupt packets streamed over a dedicated side channel to avoid blocking
  the command loop.

---

## Architecture

The deployable artifact `ps5debug-NG.elf` is a two-component build:

```
┌──────────────────────────────────────────────────────────────┐
│                       ps5debug-NG.elf                        │
│                                                              │
│   ┌───────────────────┐    injects   ┌───────────────────┐   │
│   │   installer ELF   │─────────────▶│   debugger ELF    │   │
│   │ (umtx-loaded PIE) │              │ (in SceShellCore) │   │
│   └───────────────────┘              └────────┬──────────┘   │
│                                               │              │
│                              ┌────────────────▼─────────┐    │
│                              │  - TCP server   :744     │    │
│                              │  - debug async  :755     │    │
│                              │  - klog forward :3232    │    │
│                              │  - UDP bcast    :1010    │    │
│                              └──────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

- **installer** - umtx-loaded SDK PIE. Finds SceShellCore, sets up the
  target's KEX state and syscall-origin filter, then calls the SCE-side
  `inject_remote_thread_create` primitive to run the embedded debugger as
  a SceShellCore-internal thread.
- **debugger** - runs inside SceShellCore once injected. Implements the
  wire protocol, breakpoints / watchpoints / single-step, memory scan, RPC,
  and ELF inject. Built into `debugger/build/debugger.elf`, then embedded as
  a `.rodata` blob into the installer via `.incbin`.

Running the wire protocol from inside SceShellCore is what lets `PT_ATTACH`
on game pids look kernel-side like an SCE-originated debug attach, which
PS5's AppContext gating allows. A standalone process doing `PT_ATTACH` gets
the game flagged and stops progressing.

---

## Network protocol at a glance

| Port  | Proto | Direction      | Purpose                              |
|-------|-------|----------------|--------------------------------------|
| 744   | TCP   | client → PS5   | Command server                       |
| 755   | TCP   | PS5 → client   | Async debug interrupts               |
| 3232  | TCP   | PS5 → client   | Kernel log forwarder                 |
| 1010  | UDP   | bidirectional  | Discovery beacon (`0xFFFFAAAA`)      |

Every command begins with a 12-byte header:

```c
struct cmd_packet {
    uint32_t magic;      // 0xFFAABBCC
    uint32_t cmd;        // 0xBDAA..., 0xBDBB..., 0xBDCC..., 0xBDDD...
    uint32_t datalen;    // length of request body that follows
};
```

Followed by the command's fixed request struct (if any) and any trailing
variable-length payload. The reply shape is per-command: most replies begin
with a `uint32_t` status word (some commands send two, and the info/version
commands send their data with no status word at all) - see
[PROTOCOL.md](PROTOCOL.md) for the exact sequence of each.

**Note on status words.** The status `uint32_t` on PS5 is transmitted with
its bit pairs swapped (`net_send_int32` swaps even/odd-bit positions). Clients
must account for the swap - either un-bitswap the incoming word and compare to
the server-side constants (`CMD_SUCCESS = 0x40000000`, etc., as the example
below does), or compare the raw word against the pre-swapped values
(`CMD_SUCCESS = 0x80000000`, etc.). Subsequent payload bytes are sent raw.

**Full protocol specification:** [PROTOCOL.md](PROTOCOL.md) - every command,
every packet struct, every enum, every status code, with `file:line`
citations.

---

## Command coverage

| Namespace     | Count | Examples                                                   |
|---------------|-------|------------------------------------------------------------|
| Info / ping   | 5     | `VERSION`, `FW_VERSION`, `BRANDING`, `PLATFORM_ID`, `NOP`  |
| Process       | 35    | `READ`, `WRITE`, `MAPS`, `CALL`, `SCAN_*`, `TURBOSCAN_*`, `DISASM_*` |
| Debug         | 20    | `ATTACH`, `SET_BREAKPOINT`, `GETREGS`, `GET_FSGS_BASE`, `STEP`, `CONTINUE` |
| Kernel R/W    | 3     | `KERN_BASE`, `KERN_READ`, `KERN_WRITE`                     |
| Console       | 6     | `NOTIFY`, `PRINT`, `REBOOT`, `INFO`, `END`, `FOREGROUND_APP` |
| **Total**     | **69**|                                                            |

---

## Building

Prerequisites (Ubuntu / Debian):

```sh
sudo apt install bash clang-18 lld-18
```

Build:

```sh
./build.sh
```

This builds the SDK first (one-time, cached), then the debugger, then the
installer (which embeds the debugger), then publishes `ps5debug-NG.elf` at
the top level. Subsequent runs only rebuild what changed.

Clean (including the SDK install):

```sh
./build.sh clean
```

---

## Deploying

`ps5debug-NG.elf` is loaded onto the PS5 via a umtx-based ELF loader (e.g.
elfldr from etaHEN-class loaders).

You should see a system notification confirming the payload is alive:

```
ps5debug-NG by OSR v1.3.1 loaded!
Firmware: 9.00
Coded by OpenSourcereR
Special thanks to
golden, Ctn,  SiSTRo, EchoStretch, 
Sonic-Iso & Pharaoh2k!  ❤
```

(`Firmware:` shows the running console's firmware, e.g. `9.00` or `12.40`.)

---

## Writing your own client

The protocol is deliberately simple - a raw TCP client in any language can
drive it. Example: pinging the server and reading its branding string, in
Python (don't forget the bit-pair swap on the status word):

```python
import socket, struct

PACKET_MAGIC = 0xFFAABBCC
CMD_BRANDING = 0xBD000501
CMD_SUCCESS  = 0x40000000

def bitswap32(x):
    x &= 0xFFFFFFFF
    return ((x << 1) & 0xAAAAAAAA) | ((x >> 1) & 0x55555555)

s = socket.create_connection(("<PS5_IP>", 744))
s.sendall(struct.pack("<III", PACKET_MAGIC, CMD_BRANDING, 0))
(status_raw,) = struct.unpack("<I", s.recv(4))
assert bitswap32(status_raw) == CMD_SUCCESS
(length,) = struct.unpack("<I", s.recv(4))
print("server branding:", s.recv(length).decode())
```

See [PROTOCOL.md](PROTOCOL.md) for the exact byte layout of every command,
response, and async interrupt packet.

---

## Source layout

```
.
├── build.sh                 # one-command full build
│
├── common/                  # headers + sources shared by both components
│   ├── include/             # protocol.h, sdk_shim.h, net.h, proc.h, ...
│   └── source/
│
├── debugger/                # in-SceShellCore wire-protocol debugger
│   ├── Makefile  source/  include/
│   └── third_party/         # Zydis (decoder) + Keystone (assembler)
│
├── installer/               # umtx-loaded SceShellCore installer
│   ├── Makefile  source/
│   └── source/embedded_inner.S   # embeds debugger.elf via .incbin
│
├── ps5-payload-sdk/         # vendored John Törnblom SDK
└── third_party/             # keystone-0.9.2 full source (for rebuilds)
```

Three source files (`kern_rw_fast.c`, `proc_elf.c`, `proc_remote.c`) and
`main.c` exist in **both** `debugger/source/` and `installer/source/` because
they genuinely diverge between the two builds - same code specialized for
each component's role.

---

## SDK pin

The vendored SDK is **ps5-payload-sdk v0.38** (commit
`6ae1470fd50c5791e8a8bb728627e657e36eb55a`, dated 2026-04-02). Upstream:
https://github.com/ps5-payload-dev/sdk

To upgrade the SDK:

```sh
./build.sh clean
rm -rf ps5-payload-sdk
curl -fsSL https://github.com/ps5-payload-dev/sdk/archive/refs/tags/<TAG>.tar.gz \
  | tar xz -C /tmp
mv /tmp/sdk-<TAG_WITHOUT_v> ps5-payload-sdk
./build.sh
```

---

## Credits

- **jogolden** - original public `ps4debug` and the wire protocol this project
  indirectly inherits.
- **Ctn & SiSTRo** - `ps5debug` authors; this project is wire-compatible with
  their implementation.
- **DeathRGH** - Frame4 author. Inspiration.
- **John Törnblom** - `ps5-payload-sdk`, the vendored SDK / toolchain.
- **Zydis** - x86 disassembler used in decoder-only mode (`ZYAN_NO_LIBC`,
  `-DNDEBUG`). Third-party, unmodified; MIT-licensed.
- **Keystone** - LLVM-MC-based assembler; cross-compiled here for the PS5
  payload (x86-only, `-fno-exceptions -fno-rtti`, static).
- **EchoStretch, Sonic-Iso, Pharaoh2k** - contributions and testing.
- **OSR** (OpenSourcereR) - author.

---

## License

Licensed under the **GNU General Public License v3.0** - see [LICENSE.txt](LICENSE.txt)
for the full text.

In short:
- You may use, study, modify, and redistribute this software freely.
- If you distribute a modified binary, you **must** also make the complete
  corresponding source code available under the same license.
- The software is provided **without warranty** of any kind.
