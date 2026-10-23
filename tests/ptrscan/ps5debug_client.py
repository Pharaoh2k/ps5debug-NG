"""Thin TCP client for the ps5debug-NG command server (port 744).

Everything here follows ps5debug-NG v1.3.x PROTOCOL.md.  Notes on the parts
that matter for stability:

* One request at a time per connection (the server dispatches serially per
  socket).  `_lock` enforces that from Python threads.
* If a socket error or timeout happens in the middle of a command, the byte
  stream is out of sync (a late reply would be read as the answer to the next
  command), so the connection is closed and `ProtocolError` is raised.  The
  GUI then shows "Disconnected" and you press Connect again.
* Remote calls / alloc / free all work by ptrace-hijacking a thread of the
  game (`sys_proc_cmd` -> `proc_rpc_stop_target`).  To keep that safe:
    - calls are spaced at least `call_gap` seconds apart (default 0.15 s),
    - by default a call goes through a small *stack-safe trampoline* that
      moves the stack 2 KB away from the hijacked thread's live frame, aligns
      it to 16 bytes and leaves 256 bytes of scratch, so code that writes
      stack arguments at [rsp+...] can no longer corrupt the game thread.
      `safe_calls = False` (or `call(..., safe=False)`) restores the raw call.
* Turbo scan (0xBDAACC10-17) lives in `TurboScanSession` at the bottom; it
  needs its own connection because the server keeps one scan session per
  connection and a running scan blocks that socket until it finishes.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

PACKET_MAGIC = 0xFFAABBCC
SERVER_PORT = 744
CHUNK = 0x10000
SENTINEL64 = 0xFFFFFFFFFFFFFFFF
NO_TIMEOUT = -1.0

CMD_VERSION = 0xBD000001
CMD_FW_VERSION = 0xBD000500
CMD_BRANDING = 0xBD000501
CMD_PLATFORM_ID = 0xBD000502
CMD_PROC_NOP = 0xBDAACC06
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_READ = 0xBDAA0002
CMD_PROC_WRITE = 0xBDAA0003
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INSTALL = 0xBDAA0005
CMD_PROC_CALL = 0xBDAA0006
CMD_PROC_PROTECT = 0xBDAA0008
CMD_PROC_INFO = 0xBDAA000A
CMD_PROC_ALLOC = 0xBDAA000B
CMD_PROC_FREE = 0xBDAA000C
CMD_PROC_ALLOC_HINTED = 0xBDAA000E
CMD_PROC_DISASM_REGION = 0xBDAA0020
CMD_PROC_FIND_XREFS_TO = 0xBDAA0022
CMD_PROC_READ_STACK = 0xBDAA0023
CMD_PROC_ASSEMBLE = 0xBDAA0024
CMD_PROC_SCAN_AOB = 0xBDAA0501
CMD_PROC_SCAN_AOB_MULTI = 0xBDAA0502

CMD_PROC_AUTH = 0xBDAACCFF
CMD_PROC_READ_MULTI = 0xBDAACC03      # "SCAN_GET": bulk read of many (addr, len) pairs
CMD_PROC_WRITE_MULTI = 0xBDAACC04     # bulk write (freeze lists)
CMD_PROC_TURBOSCAN_CAPS = 0xBDAACC10
CMD_PROC_TURBOSCAN_START = 0xBDAACC11
CMD_PROC_TURBOSCAN_COUNT = 0xBDAACC12
CMD_PROC_TURBOSCAN_GET = 0xBDAACC13
CMD_PROC_TURBOSCAN_END = 0xBDAACC14
CMD_PROC_TURBOSCAN_CONFIG = 0xBDAACC15
CMD_PROC_TURBOSCAN_REGIONS = 0xBDAACC16
CMD_PROC_TURBOSCAN_CANCEL = 0xBDAACC17

CMD_DEBUG_ATTACH = 0xBDBB0001
CMD_DEBUG_DETACH = 0xBDBB0002
CMD_DEBUG_SET_BREAKPOINT = 0xBDBB0003
CMD_DEBUG_SET_WATCHPOINT = 0xBDBB0004
CMD_DEBUG_GET_THREAD_LIST = 0xBDBB0005
CMD_DEBUG_SUSPEND_THREAD = 0xBDBB0006
CMD_DEBUG_RESUME_THREAD = 0xBDBB0007
CMD_DEBUG_GETREGS = 0xBDBB0008
CMD_DEBUG_SETREGS = 0xBDBB0009
CMD_DEBUG_GETFPREGS = 0xBDBB000A
CMD_DEBUG_SETFPREGS = 0xBDBB000B
CMD_DEBUG_CONTINUE = 0xBDBB0010
CMD_DEBUG_THREAD_INFO = 0xBDBB0011
CMD_DEBUG_STEP = 0xBDBB0012
CMD_DEBUG_STEP_THREAD = 0xBDBB0013

# Status words as they appear on the wire (bit-swapped by the server).
STATUS_SUCCESS = 0x80000000
STATUS_ERROR = 0xF0000001
STATUS_DATA_NULL = 0xF0000003
STATUS_ALREADY_DEBUG = 0xF0000004
STATUS_INVALID_INDEX = 0xF0000005

STATUS_NAMES = {
    STATUS_SUCCESS: "SUCCESS",
    STATUS_ERROR: "ERROR",
    STATUS_DATA_NULL: "DATA_NULL",
    STATUS_ALREADY_DEBUG: "ALREADY_DEBUG",
    STATUS_INVALID_INDEX: "INVALID_INDEX",
}

PROT_NONE = 0
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

AUTH_MAGIC = 0xBB40E64D

# Turbo scan engine bits (CAPS) and request flags (START / COUNT)
TSE_SIMD_COMPARE = 0x001
TSE_ALIASING = 0x002
TSE_SERVER_RESIDENT = 0x004
TSE_SNAPSHOT = 0x008
TSE_SNAPSHOT_SEGMENTS = 0x010
TSE_SNAPSHOT_CONFIG = 0x020
TSE_SNAPSHOT_FIRST = 0x040
TSE_SNAPSHOT_PREVIOUS = 0x080
TSE_PARALLEL_COMPARE = 0x100
TSE_RESCAN_ALIASING = 0x200
TSE_FLOAT_POLICY = 0x400
TSE_COMPACT_SIMPLE_SNAPSHOT = 0x800
TSE_POINTER_SCAN = 0x1000          # modified payload: 0xBDAACC30 pointer-scan level
CMD_PROC_PTRSCAN = 0xBDAACC30

TS_USE_ALIASING = 0x001
TS_SERVER_RESIDENT = 0x002
TS_SNAPSHOT = 0x004
TS_SNAPSHOT_INCLUDE_ZEROS = 0x008
TS_SNAPSHOT_SEGMENTS = 0x010
TS_SNAPSHOT_KEEP_FIRST = 0x020
TS_SNAPSHOT_KEEP_PREVIOUS = 0x040
TS_PARALLEL_COMPARE = 0x080
TS_RESCAN_ALIASING = 0x100
TS_FLOAT_SIMPLE = 0x200
TS_FLOAT_EXACT = 0x400

# compare types that read the scan value / need the previous value (scan_compare.c tables)
CMP_NEEDS_VALUE = {0, 1, 2, 3, 4, 6, 8, 12}
CMP_NEEDS_PREVIOUS = {5, 6, 7, 8, 9, 10}
# value types: size in bytes (10 = array of bytes, size from the pattern)
VALUE_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 8, 7: 8, 8: 4, 9: 8}


class ProtocolError(RuntimeError):
    pass


@dataclass
class ProcessEntry:
    name: str
    pid: int


@dataclass
class MapEntry:
    name: str
    start: int
    end: int
    offset: int
    prot: int


@dataclass
class ProcInfo:
    pid: int
    name: str
    path: str
    titleid: str
    contentid: str


@dataclass
class StackFrame:
    rbp: int
    rsp: int
    saved_rbp: int
    ret_addr: int
    flags: int
    locals: bytes
    code: bytes


@dataclass
class DisasmEntry:
    addr: int
    rip_rel_target: int
    mem_disp: int
    length: int
    kind: int  # 0x01 call, 0x02 ret, 0x04 jmp, 0x08 jcc, 0x10 mem, 0x20 rip-rel, 0x40 read, 0x80 write
    mem_base_reg: int
    mem_index_reg: int
    mem_scale: int
    mnemonic_lo: int


@dataclass
class TurboCaps:
    version: int
    engines: int
    max_threads: int

    def has(self, bit: int) -> bool:
        return bool(self.engines & bit)


@dataclass
class RegionInfo:
    start: int
    end: int
    prot: int
    flags: int      # bit0 = uncached (PCD)
    mbps: int

    @property
    def uncached(self) -> bool:
        return bool(self.flags & 1)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    if n <= 0:
        return b""
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        k = sock.recv_into(view[got:], n - got)
        if not k:
            raise ProtocolError("connection closed by the console while reading")
        got += k
    return bytes(buf)


# ----------------------------------------------------------------------------
# auth (PROTOCOL.md 1.8): xorshift keystream seeded 200,300,400,500
# ----------------------------------------------------------------------------
def _auth_keystream() -> bytes:
    m = 0xFFFFFFFF
    s1, s2, s3, s4 = 200, 300, 400, 500
    out = bytearray(256)
    for i in range(256):
        s1 = ((s1 << 18) & 0xFFF80000) ^ (((s1 ^ (s1 << 6)) & m) >> 13)
        s2 = ((s2 << 2) & 0xFFFFFFE0) ^ (((s2 ^ (s2 << 2)) & m) >> 27)
        s3 = ((s3 << 7) & 0xFFFFF800) ^ (((s3 ^ (s3 << 13)) & m) >> 21)
        s4 = ((s4 << 13) & 0xFFF00000) ^ (((s4 ^ (s4 << 3)) & m) >> 12)
        out[i] = (s1 ^ s2 ^ s3 ^ s4) & 0xFF
    return bytes(out)


_KEYSTREAM = _auth_keystream()


# ----------------------------------------------------------------------------
# stack-safe call trampoline
# ----------------------------------------------------------------------------
TRAMP_SLOT = 64
TRAMP_POOL = 0x4000          # 256 trampolines per pool


def build_trampoline(target: int) -> bytes:
    """x86-64 stub the server's CMD_PROC_CALL jumps to instead of `target`.

        mov  r11, rsp             ; entry rsp: [rsp] = the server's return address
        lea  rsp, [rsp-0x800]     ; get well away from the hijacked thread's frame + red zone
        and  rsp, -16             ; SysV alignment
        push r11
        push r11                  ; saved entry rsp (twice keeps 16-byte alignment)
        sub  rsp, 0x100           ; scratch: code writing [rsp+8..] hits this, not the game
        xor  eax, eax             ; al = 0 vector args (variadic callees)
        mov  r11, target
        call r11                  ; callee sees a correctly aligned stack
        add  rsp, 0x100
        pop  r11
        pop  rsp                  ; back to the entry rsp
        ret                       ; -> server's return address (ends the call)

    Registers are clobbered freely: the server restores the whole register
    set of the hijacked thread after the call.
    """
    code = (
        b"\x49\x89\xE3"                          # mov r11, rsp
        b"\x48\x8D\xA4\x24\x00\xF8\xFF\xFF"      # lea rsp, [rsp-0x800]
        b"\x48\x83\xE4\xF0"                      # and rsp, -16
        b"\x41\x53"                              # push r11
        b"\x41\x53"                              # push r11
        b"\x48\x81\xEC\x00\x01\x00\x00"          # sub rsp, 0x100
        b"\x31\xC0"                              # xor eax, eax
        b"\x49\xBB" + struct.pack("<Q", target & 0xFFFFFFFFFFFFFFFF) +   # mov r11, imm64
        b"\x41\xFF\xD3"                          # call r11
        b"\x48\x81\xC4\x00\x01\x00\x00"          # add rsp, 0x100
        b"\x41\x5B"                              # pop r11
        b"\x5C"                                  # pop rsp
        b"\xC3"                                  # ret
    )
    assert len(code) <= TRAMP_SLOT
    return code.ljust(TRAMP_SLOT, b"\xCC")


class _TrampPool:
    def __init__(self, base: int) -> None:
        self.base = base
        self.used = 0
        self.slots: dict[int, int] = {}   # target -> trampoline address


class PS5DebugClient:
    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._lock = threading.RLock()
        self.host = ""
        self.port = SERVER_PORT
        self.timeout = 30.0
        # remote-call safety (see module docstring)
        self.safe_calls = True
        self.call_gap = 0.15
        self._last_hijack = 0.0
        self._tramps: dict[int, _TrampPool] = {}
        self.on_disconnect: Optional[Callable[[str], None]] = None
        self.authed = False

    # ------------------------------------------------------------------
    # connection
    # ------------------------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self, host: str, port: int = SERVER_PORT, timeout: float = 8.0) -> None:
        self.close()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        sock.settimeout(self.timeout)
        self._sock = sock
        self.host = host
        self.port = port
        self.authed = False
        self._tramps.clear()

    def clone(self) -> "PS5DebugClient":
        """A second, independent connection to the same console (same settings)."""
        c = PS5DebugClient()
        c.safe_calls, c.call_gap = self.safe_calls, self.call_gap
        c.connect(self.host, self.port)
        return c

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        self.authed = False
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _broken(self, why: str) -> ProtocolError:
        """The stream can no longer be trusted: drop the connection."""
        was = self._sock is not None
        self.close()
        if was and self.on_disconnect:
            try:
                self.on_disconnect(why)
            except Exception:
                pass
        return ProtocolError(f"{why} - the connection was closed, press Connect again")

    def _sock_or_raise(self) -> socket.socket:
        sock = self._sock
        if sock is None:
            raise ProtocolError("not connected")
        return sock

    # every command body runs inside _txn(): socket failures mid-command kill the connection
    class _Txn:
        def __init__(self, cli: "PS5DebugClient", what: str, timeout: Optional[float]) -> None:
            self.cli, self.what, self.timeout = cli, what, timeout
            self.old: Optional[float] = None

        def __enter__(self):
            self.cli._lock.acquire()
            if self.timeout is not None and self.cli._sock is not None:
                self.old = self.cli._sock.gettimeout()
                # NO_TIMEOUT: long scans - block until the console answers (cancel / force-close ends it)
                self.cli._sock.settimeout(None if self.timeout == NO_TIMEOUT else self.timeout)
            return self

        def __exit__(self, et, ev, tb):
            try:
                if self.timeout is not None and self.cli._sock is not None:
                    try:
                        self.cli._sock.settimeout(self.old)
                    except OSError:
                        pass
                if et is None:
                    return False
                if issubclass(et, socket.timeout):
                    raise self.cli._broken(f"{self.what}: no answer from the console") from None
                if issubclass(et, (OSError, ConnectionError)):
                    raise self.cli._broken(f"{self.what}: connection error ({ev})") from None
                if issubclass(et, ProtocolError) and "connection closed" in str(ev):
                    raise self.cli._broken(f"{self.what}: console closed the connection") from None
                return False
            finally:
                self.cli._lock.release()

    def _txn(self, what: str, timeout: Optional[float] = None) -> "PS5DebugClient._Txn":
        return PS5DebugClient._Txn(self, what, timeout)

    def _send_packet(self, cmd: int, body: bytes = b"") -> None:
        sock = self._sock_or_raise()
        header = struct.pack("<III", PACKET_MAGIC, cmd, len(body))
        sock.sendall(header + body)

    def _recv(self, n: int) -> bytes:
        return _recv_exact(self._sock_or_raise(), n)

    def _recv_u32(self) -> int:
        return struct.unpack("<I", self._recv(4))[0]

    def _recv_u64(self) -> int:
        return struct.unpack("<Q", self._recv(8))[0]

    def _recv_status(self) -> int:
        return self._recv_u32()

    def _expect_success(self, what: str) -> None:
        status = self._recv_status()
        if status != STATUS_SUCCESS:
            name = STATUS_NAMES.get(status, f"0x{status:08X}")
            raise ProtocolError(f"{what} failed: {name}")

    def send_cmd(self, cmd: int, body: bytes = b"") -> None:
        with self._txn("send"):
            self._send_packet(cmd, body)

    # ------------------------------------------------------------------
    # info
    # ------------------------------------------------------------------
    def ping(self) -> None:
        with self._txn("ping", 6.0):
            self._send_packet(CMD_PROC_NOP)
            self._expect_success("ping")

    def version(self) -> str:
        with self._txn("version"):
            self._send_packet(CMD_VERSION)
            length = self._recv_u32()
            return self._recv(length).decode("utf-8", "replace")

    def branding(self) -> str:
        with self._txn("branding"):
            self._send_packet(CMD_BRANDING)
            length = self._recv_u32()
            return self._recv(length).decode("utf-8", "replace")

    def fw_version(self) -> int:
        with self._txn("fw version"):
            self._send_packet(CMD_FW_VERSION)
            return struct.unpack("<H", self._recv(2))[0]

    def foreground_app(self) -> tuple[int, str, str, str]:
        """(pid, title id, name, app version) of the game in front; pid 0 = no game running."""
        with self._txn("foreground app"):
            self._send_packet(0xBDDD0006)
            self._expect_success("foreground app")
            blob = self._recv(140)
        pid, tid, _cid, name, ver = struct.unpack("<I16s64s40s16s", blob)
        dec = lambda b: b.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        return pid, dec(tid).upper(), dec(name), dec(ver)

    def list_processes(self) -> list[ProcessEntry]:
        with self._txn("proc list"):
            self._send_packet(CMD_PROC_LIST)
            self._expect_success("proc list")
            count = self._recv_u32()
            blob = self._recv(count * 36)
        out: list[ProcessEntry] = []
        for i in range(count):
            name_raw, pid = struct.unpack_from("<32si", blob, i * 36)
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
            out.append(ProcessEntry(name=name, pid=pid))
        return out

    def proc_info(self, pid: int) -> ProcInfo:
        with self._txn("proc info"):
            self._send_packet(CMD_PROC_INFO, struct.pack("<I", pid))
            self._expect_success("proc info")
            blob = self._recv(188)
        pid_v, name, path, titleid, contentid = struct.unpack("<I40s64s16s64s", blob)
        dec = lambda b: b.split(b"\x00", 1)[0].decode("utf-8", "replace")
        return ProcInfo(pid_v, dec(name), dec(path), dec(titleid), dec(contentid))

    def maps(self, pid: int) -> list[MapEntry]:
        with self._txn("maps"):
            self._send_packet(CMD_PROC_MAPS, struct.pack("<I", pid))
            self._expect_success("maps")
            count = self._recv_u32()
            blob = self._recv(count * 58)
        out: list[MapEntry] = []
        for i in range(count):
            name_raw, start, end, offset, prot = struct.unpack_from("<32sQQQH", blob, i * 58)
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
            out.append(MapEntry(name, start, end, offset, prot))
        return out

    # ------------------------------------------------------------------
    # memory
    # ------------------------------------------------------------------
    def read(self, pid: int, address: int, length: int) -> bytes:
        if length <= 0:
            return b""
        with self._txn("read"):
            self._send_packet(CMD_PROC_READ, struct.pack("<IQI", pid, address, length))
            self._expect_success("read")
            return self._recv(length)

    def write(self, pid: int, address: int, data: bytes) -> None:
        if not data:
            return
        with self._txn("write"):
            self._send_packet(CMD_PROC_WRITE, struct.pack("<IQI", pid, address, len(data)))
            self._expect_success("write (ack)")
            sock = self._sock_or_raise()
            view = memoryview(data)
            for off in range(0, len(data), CHUNK):
                sock.sendall(view[off : off + CHUNK])
            self._expect_success("write")

    def write_multi(self, pid: int, entries: list[tuple[int, bytes]], want_status: bool = False) -> Optional[bytes]:
        """Many writes in one exchange (0xBDAACC04) - used by the freeze list.
        Returns the per-entry status array when `want_status` (0 = ok)."""
        entries = [(a, d) for a, d in entries if d][:0xFFFF]
        if not entries:
            return b"" if want_status else None
        payload = bytearray()
        for addr, data in entries:
            if len(data) > 0x100000:
                raise ProtocolError("write_multi: entry larger than 1 MiB")
            payload += struct.pack("<QI", addr, len(data)) + data
        with self._txn("write multi"):
            self._send_packet(CMD_PROC_WRITE_MULTI,
                              struct.pack("<III", pid, len(entries), 1 if want_status else 0))
            self._expect_success("write multi (ack)")
            self._sock_or_raise().sendall(payload)
            status = self._recv(len(entries)) if want_status else None
            final = self._recv_status()
        if final != STATUS_SUCCESS and not want_status:
            raise ProtocolError("write multi: some entries failed")
        return status

    def read_multi(self, pid: int, entries: list[tuple[int, int]]) -> list[bytes]:
        """Bulk read (0xBDAACC03): one exchange for many (address, length) pairs.
        Needs auth (call auth() once per console session)."""
        if not entries:
            return []
        self.ensure_auth()
        body = b"".join(struct.pack("<QI", a, n) for a, n in entries)
        total = sum(n for _a, n in entries)
        with self._txn("read multi"):
            self._send_packet(CMD_PROC_READ_MULTI, struct.pack("<II", pid, len(entries)))
            self._expect_success("read multi")
            self._sock_or_raise().sendall(body)
            blob = self._recv(total)
            if self._recv_u64() != SENTINEL64:
                raise self._broken("read multi: missing end marker")
        out, off = [], 0
        for _a, n in entries:
            out.append(blob[off : off + n])
            off += n
        return out

    # ------------------------------------------------------------------
    # remote procedure helpers (these hijack a game thread - keep them spaced)
    # ------------------------------------------------------------------
    def _hijack_gate(self) -> None:
        """Wait so two thread-hijacking requests are at least `call_gap` apart.
        Called with the lock held, so the gap holds across every thread of the app."""
        gap = max(0.0, float(self.call_gap or 0))
        wait = self._last_hijack + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    def _hijack_done(self) -> None:
        self._last_hijack = time.monotonic()

    def alloc(self, pid: int, length: int, timeout: float = 15.0) -> int:
        """Allocate memory in the target. If the console does not answer within
        `timeout` seconds the connection is closed (a late reply would otherwise
        corrupt the next command) and a clear error is raised."""
        with self._lock:
            self._hijack_gate()
            try:
                with self._txn("alloc", timeout):
                    self._send_packet(CMD_PROC_ALLOC, struct.pack("<II", pid, length))
                    self._expect_success("alloc")
                    return self._recv_u64()
            except ProtocolError as exc:
                if "no answer" in str(exc):
                    raise ProtocolError(
                        f"alloc: no answer from the console within {timeout:.0f}s, so the connection was closed. "
                        "The game process is not responding to the allocation. Press Diagnose after "
                        "reconnecting; if ping and maps work but alloc does not, the game is stuck (a function "
                        "that never returned, or the debugger holding it stopped) - continue/detach the "
                        "debugger or restart the game.") from None
                raise
            finally:
                self._hijack_done()

    def alloc_hinted(self, pid: int, hint: int, length: int) -> int:
        with self._lock:
            self._hijack_gate()
            try:
                with self._txn("hinted alloc", 15.0):
                    self._send_packet(CMD_PROC_ALLOC_HINTED, struct.pack("<IQI", pid, hint, length))
                    status = self._recv_status()
                    addr = self._recv_u64()
            finally:
                self._hijack_done()
        if status != STATUS_SUCCESS:
            name = STATUS_NAMES.get(status, f"0x{status:08X}")
            raise ProtocolError(f"hinted alloc failed: {name} (addr=0x{addr:X})")
        return addr

    def free(self, pid: int, address: int, length: int) -> None:
        with self._lock:
            self._hijack_gate()
            try:
                with self._txn("free", 15.0):
                    self._send_packet(CMD_PROC_FREE, struct.pack("<IQI", pid, address, length))
                    self._expect_success("free")
            finally:
                self._hijack_done()
            # a freed block may have held trampolines
            pool = self._tramps.get(pid)
            if pool and pool.base == address:
                self._tramps.pop(pid, None)

    def protect(self, pid: int, address: int, length: int, prot: int) -> None:
        # kernel-side mprotect: no thread hijack
        with self._txn("protect"):
            self._send_packet(CMD_PROC_PROTECT, struct.pack("<IQII", pid, address, length, prot))
            self._expect_success("protect")

    def install_rpc(self, pid: int) -> int:
        """Legacy install opcode; current NG server returns stub=0."""
        with self._txn("install"):
            self._send_packet(CMD_PROC_INSTALL, struct.pack("<I", pid))
            self._expect_success("install")
            return self._recv_u64()

    def _trampoline(self, pid: int, target: int) -> int:
        pool = self._tramps.get(pid)
        if pool is not None and target in pool.slots:
            return pool.slots[target]
        if pool is None or pool.used + TRAMP_SLOT > TRAMP_POOL:
            base = self.alloc(pid, TRAMP_POOL)
            pool = _TrampPool(base)
            self._tramps[pid] = pool
        addr = pool.base + pool.used
        self.write(pid, addr, build_trampoline(target))
        pool.used += TRAMP_SLOT
        pool.slots[target] = addr
        return addr

    def forget_trampolines(self, pid: Optional[int] = None) -> None:
        if pid is None:
            self._tramps.clear()
        else:
            self._tramps.pop(pid, None)

    def call(
        self,
        pid: int,
        rip: int,
        rdi: int = 0,
        rsi: int = 0,
        rdx: int = 0,
        rcx: int = 0,
        r8: int = 0,
        r9: int = 0,
        rpcstub: int = 0,
        safe: Optional[bool] = None,
        timeout: float = 30.0,
    ) -> int:
        """Run `rip(rdi, rsi, rdx, rcx, r8, r9)` in the target and return RAX.

        Never retried here: if the call failed after the function already ran,
        a retry would run it twice (the server itself already retries the
        hijack setup when that fails)."""
        use_safe = self.safe_calls if safe is None else safe
        with self._lock:
            entry = rip
            if use_safe and not rpcstub:
                entry = self._trampoline(pid, rip)
            body = struct.pack("<IQQQQQQQQ", pid, rpcstub, entry, rdi, rsi, rdx, rcx, r8, r9)
            self._hijack_gate()
            try:
                with self._txn("call", timeout):
                    self._send_packet(CMD_PROC_CALL, body)
                    status = self._recv_status()
                    if status != STATUS_SUCCESS:
                        name = STATUS_NAMES.get(status, f"0x{status:08X}")
                        raise ProtocolError(
                            f"call failed: {name}" + (
                                " (the console refuses calls while the debugger holds the game stopped, "
                                "or the game thread could not be borrowed - wait a moment and try once more)"
                                if status == STATUS_ERROR else ""))
                    blob = self._recv(12)
            finally:
                self._hijack_done()
        _pid, rax = struct.unpack("<IQ", blob)
        return rax

    # ------------------------------------------------------------------
    # Debugger (ps5debug-NG). Commands go over this connection; stop events
    # (breakpoint / step / signal) arrive separately on TCP 755 - see
    # debugger_core.InterruptListener.
    # ------------------------------------------------------------------
    def debug_attach(self, pid: int) -> None:
        with self._txn("attach", 20.0):
            self._send_packet(CMD_DEBUG_ATTACH, struct.pack("<I", pid))
            self._expect_success("attach")

    def debug_detach(self) -> None:
        with self._txn("detach", 20.0):
            self._send_packet(CMD_DEBUG_DETACH)
            self._expect_success("detach")

    def debug_set_breakpoint(self, index: int, enabled: bool, address: int) -> None:
        with self._txn("set breakpoint"):
            self._send_packet(
                CMD_DEBUG_SET_BREAKPOINT, struct.pack("<IIQ", index, 1 if enabled else 0, address)
            )
            self._expect_success("set breakpoint")

    def debug_set_watchpoint(
        self, index: int, enabled: bool, length: int, breaktype: int, address: int
    ) -> None:
        """length / breaktype are the raw DR7 encodings (length: 0=1B 1=2B 2=8B 3=4B;
        breaktype: 0=exec 1=write 3=read/write)."""
        with self._txn("set watchpoint"):
            self._send_packet(
                CMD_DEBUG_SET_WATCHPOINT,
                struct.pack("<IIIIQ", index, 1 if enabled else 0, length, breaktype, address),
            )
            self._expect_success("set watchpoint")

    def debug_threads(self) -> list[int]:
        with self._txn("thread list"):
            self._send_packet(CMD_DEBUG_GET_THREAD_LIST)
            self._expect_success("thread list")
            count = self._recv_u32()
            blob = self._recv(count * 4)
        return list(struct.unpack(f"<{count}I", blob)) if count else []

    def debug_thread_info(self, lwpid: int) -> tuple[int, str]:
        """(priority, name) of a thread."""
        with self._txn("thread info"):
            self._send_packet(CMD_DEBUG_THREAD_INFO, struct.pack("<I", lwpid))
            self._expect_success("thread info")
            blob = self._recv(40)
        _lwp, prio, name = struct.unpack("<II32s", blob)
        return prio, name.split(b"\x00", 1)[0].decode("utf-8", "replace")

    def debug_suspend_thread(self, lwpid: int) -> None:
        with self._txn("suspend thread"):
            self._send_packet(CMD_DEBUG_SUSPEND_THREAD, struct.pack("<I", lwpid))
            self._expect_success("suspend thread")

    def debug_resume_thread(self, lwpid: int) -> None:
        with self._txn("resume thread"):
            self._send_packet(CMD_DEBUG_RESUME_THREAD, struct.pack("<I", lwpid))
            self._expect_success("resume thread")

    def debug_getregs(self, lwpid: int) -> bytes:
        """176-byte FreeBSD amd64 `struct reg` for one thread."""
        with self._txn("get regs"):
            self._send_packet(CMD_DEBUG_GETREGS, struct.pack("<I", lwpid))
            self._expect_success("get regs")
            return self._recv(176)

    def debug_setregs(self, lwpid: int, regs: bytes) -> None:
        if len(regs) != 176:
            raise ProtocolError("register blob must be 176 bytes")
        with self._txn("set regs"):
            self._send_packet(CMD_DEBUG_SETREGS, struct.pack("<II", lwpid, len(regs)))
            self._expect_success("set regs (ack)")
            self._sock_or_raise().sendall(regs)
            self._expect_success("set regs")

    def debug_getfpregs(self, lwpid: int) -> bytes:
        """832-byte xsave image (FXSAVE area: x87, MXCSR at 0x18, XMM0-15 at 0xA0; YMM upper halves at 0x240)."""
        with self._txn("get fp regs"):
            self._send_packet(CMD_DEBUG_GETFPREGS, struct.pack("<I", lwpid))
            self._expect_success("get fp regs")
            return self._recv(832)

    def debug_setfpregs(self, lwpid: int, fpu: bytes) -> None:
        """Send back a full image (round-tripped from GETFPREGS) so the xstate header stays valid."""
        if len(fpu) not in (512, 832):
            raise ProtocolError("FPU blob must be 832 (xsave) or 512 (fxsave) bytes")
        with self._txn("set fp regs"):
            self._send_packet(CMD_DEBUG_SETFPREGS, struct.pack("<II", lwpid, len(fpu)))
            self._expect_success("set fp regs (ack)")
            self._sock_or_raise().sendall(fpu)
            self._expect_success("set fp regs")

    def debug_continue(self, action: int = 0) -> None:
        """0 = resume the whole process, 1 = stop (SIGSTOP), 2 = kill."""
        with self._txn("continue/stop"):
            self._send_packet(CMD_DEBUG_CONTINUE, struct.pack("<I", action))
            self._expect_success("continue/stop")

    def debug_step(self) -> None:
        """Single-step the process; the stop event arrives on port 755."""
        with self._txn("step"):
            self._send_packet(CMD_DEBUG_STEP)
            self._expect_success("step")

    def debug_step_thread(self, lwpid: int) -> None:
        with self._txn("step thread"):
            self._send_packet(CMD_DEBUG_STEP_THREAD, struct.pack("<I", lwpid))
            self._expect_success("step thread")

    # ------------------------------------------------------------------
    # Server-side helpers (Zydis decoder / RBP-chain stack walker)
    # ------------------------------------------------------------------
    def read_stack(self, pid: int, rbp: int, rsp: int, depth: int = 16) -> list[StackFrame]:
        """Server walks the RBP chain (max 64 frames) and returns each frame."""
        with self._txn("read stack"):
            self._send_packet(CMD_PROC_READ_STACK, struct.pack("<IQQI", pid, rbp, rsp, depth))
            self._expect_success("read stack")
            blen = self._recv_u32()
            blob = self._recv(blen)
        if len(blob) < 4:
            return []
        n = struct.unpack_from("<I", blob, 0)[0]
        off = 4
        frames: list[StackFrame] = []
        for _ in range(n):
            if off + 44 > len(blob):
                break
            f_rbp, f_rsp, saved, ret, flags, llen, clen = struct.unpack_from("<QQQQIII", blob, off)
            off += 44
            loc = blob[off : off + llen]
            off += llen
            code = blob[off : off + clen]
            off += clen
            frames.append(StackFrame(f_rbp, f_rsp, saved, ret, flags, loc, code))
        return frames

    def disasm_region(
        self, pid: int, address: int, length: int, max_entries: int = 256
    ) -> list[DisasmEntry]:
        """Server-side Zydis decode: instruction boundaries + control-flow metadata
        (not text). max_entries must be 1..1000000."""
        out: list[DisasmEntry] = []
        with self._txn("disasm"):
            self._send_packet(
                CMD_PROC_DISASM_REGION, struct.pack("<IQII", pid, address, length, max_entries)
            )
            self._expect_success("disasm")
            while True:
                raw = self._recv(32)
                if raw == b"\xff" * 32:
                    break
                addr, rel, disp, ln, kind, base, idx, scale, mn, _pad = struct.unpack("<QQqBBBBBBH", raw)
                out.append(DisasmEntry(addr, rel, disp, ln, kind, base, idx, scale, mn))
        return out

    def find_xrefs_to(self, pid: int, scan_address: int, scan_length: int, target: int) -> list[int]:
        """Addresses of instructions in [scan_address, +scan_length) whose
        RIP-relative target equals `target`."""
        out: list[int] = []
        with self._txn("find xrefs", 120.0):
            self._send_packet(
                CMD_PROC_FIND_XREFS_TO, struct.pack("<IQIQ", pid, scan_address, scan_length, target)
            )
            self._expect_success("find xrefs")
            while True:
                v = self._recv_u64()
                if v == SENTINEL64:
                    break
                out.append(v)
        return out

    # ------------------------------------------------------------------
    # array-of-bytes scans (server side, no auth needed)
    # ------------------------------------------------------------------
    def scan_aob(self, pid: int, address: int, length: int, pattern: bytes, mask: bytes,
                 nth: int = 1, unique: bool = False) -> int:
        """Address of the nth match (1-based) in [address, address+length), 0 if none.
        unique=True: 0 when there is more than `nth` match."""
        if not pattern or len(mask) != len(pattern):
            raise ProtocolError("aob: pattern and mask must have the same length")
        body = struct.pack("<IQIBBI", pid, address, min(length, 0xFFFFFFFF), max(1, min(nth, 255)),
                           1 if unique else 0, len(pattern))
        with self._txn("aob scan", 120.0):
            self._send_packet(CMD_PROC_SCAN_AOB, body)
            self._expect_success("aob scan")
            self._sock_or_raise().sendall(bytes(pattern) + bytes(mask))
            self._expect_success("aob scan (setup)")
            addr = self._recv_u64()
            self._expect_success("aob scan (end)")
        return addr

    def scan_aob_all(self, pid: int, address: int, length: int, pattern: bytes, mask: bytes,
                     limit: int = 32) -> list[int]:
        """Up to `limit` matches in one pass (multi-pattern scan with target counts 1..limit)."""
        limit = max(1, min(limit, 255))
        blob = b"".join(struct.pack("<BI", k, len(pattern)) + bytes(pattern) + bytes(mask)
                        for k in range(1, limit + 1))
        body = struct.pack("<IQIBI", pid, address, min(length, 0xFFFFFFFF), 0, len(blob))
        with self._txn("aob scan", 120.0):
            self._send_packet(CMD_PROC_SCAN_AOB_MULTI, body)
            self._expect_success("aob scan")
            self._sock_or_raise().sendall(blob)
            self._expect_success("aob scan (setup)")
            raw = self._recv(8 * limit)
            self._expect_success("aob scan (end)")
        out = []
        for a in struct.unpack(f"<{limit}Q", raw):
            if not a:
                break
            out.append(a)
        return sorted(set(out))

    # ------------------------------------------------------------------
    # auth + turbo scan
    # ------------------------------------------------------------------
    def auth(self) -> None:
        """CMD_PROC_AUTH handshake (enables the staged / turbo scan commands)."""
        with self._txn("auth"):
            self._send_packet(CMD_PROC_AUTH, struct.pack("<II", AUTH_MAGIC, 2))
            self._expect_success("auth")
            n = struct.unpack("<H", self._recv(2))[0]
            challenge = self._recv(n)
            resp = bytes(b ^ _KEYSTREAM[i & 0xFF] for i, b in enumerate(challenge))
            self._sock_or_raise().sendall(resp)
            self._expect_success("auth (response)")
        self.authed = True

    def ensure_auth(self) -> None:
        if not self.authed:
            self.auth()

    def ptrscan_level(self, pid: int, segments: list[tuple[int, int]], frontier: bytes, max_off: int,
                      alias: bool = True, on_progress: Optional[Callable[[int, int], None]] = None
                      ) -> tuple[bytes, int, int, int]:
        """One console pass (modified payload, CAPS bit TSE_POINTER_SCAN): every 8-byte slot in `segments`
        whose value v has  f - max_off <= v <= f  for an address f of `frontier` (sorted little-endian u64s).
        -> (records blob of {u64 slot, u64 value}, total hits, bytes scanned, status 0 ok/1 cancelled/2 capped).
        Bytes the console could not read in this pass are left in self.last_ptrscan_unreadable."""
        self.ensure_auth()
        nfront = len(frontier) // 8
        hdr = struct.pack("<IIQII", pid, 1 if alias else 0, max_off, len(segments), nfront)
        segblob = b"".join(struct.pack("<QQ", a, n) for a, n in segments)
        parts: list[bytes] = []
        with self._txn("pointer scan", NO_TIMEOUT):
            self._send_packet(CMD_PROC_PTRSCAN, hdr)
            self._expect_success("pointer scan")
            sock = self._sock_or_raise()
            sock.sendall(segblob)
            sock.sendall(frontier)
            self._expect_success("pointer scan (setup)")
            while True:
                n = self._recv_u32()
                if n == 0:
                    break
                if n == 0xFFFFFFFF:
                    done, total = struct.unpack("<QQ", self._recv(16))
                    if on_progress:
                        on_progress(done, total)
                    continue
                if n > (1 << 20):
                    raise self._broken("pointer scan: bad block size")
                parts.append(self._recv(n * 16))
            total_hits, scanned = struct.unpack("<QQ", self._recv(16))
            # newer payloads add u64 bytes_unreadable before the status; older ones send
            # u32 status + the SUCCESS word right away.  bytes_unreadable is < 2^47, so a high
            # half equal to the SUCCESS word can only be the older layout.
            lo, hi = struct.unpack("<II", self._recv(8))
            if hi == STATUS_SUCCESS and lo <= 2:
                status, unreadable = lo, 0
            else:
                unreadable = lo | (hi << 32)
                status = self._recv_u32()
                self._expect_success("pointer scan (end)")
        self.last_ptrscan_unreadable = unreadable
        return b"".join(parts), total_hits, scanned, status

    def turbo_caps(self, timeout: float = 4.0) -> Optional[TurboCaps]:
        """None when the payload has no turbo scan (old server: no answer or ERROR)."""
        try:
            with self._txn("turbo caps", timeout):
                self._send_packet(CMD_PROC_TURBOSCAN_CAPS)
                status = self._recv_status()
                if status != STATUS_SUCCESS:
                    return None
                v, eng, thr, _r = struct.unpack("<IIII", self._recv(16))
        except ProtocolError:
            return None
        return TurboCaps(v, eng, thr)

    def turbo_regions(self, pid: int, max_regions: int = 0, probe_bytes: int = 0) -> list[RegionInfo]:
        self.ensure_auth()
        with self._txn("turbo regions", 120.0):
            self._send_packet(CMD_PROC_TURBOSCAN_REGIONS, struct.pack("<IIII", pid, max_regions, probe_bytes, 0))
            self._expect_success("region classify")
            n = self._recv_u32()
            blob = self._recv(n * 32)
            self._expect_success("region classify (end)")
        out = []
        for i in range(n):
            st, en, prot, flags, mbps, _r = struct.unpack_from("<QQIIII", blob, i * 32)
            out.append(RegionInfo(st, en, prot, flags, mbps))
        return out

    def turbo_config(self, ram_mb: int = 0, spill_dir: str = "") -> None:
        self.ensure_auth()
        p = spill_dir.encode("utf-8")[:63]
        with self._txn("turbo config"):
            self._send_packet(CMD_PROC_TURBOSCAN_CONFIG, struct.pack("<II", ram_mb, len(p)) + p)
            self._expect_success("turbo config")

    def turbo_cancel(self, pid: int) -> None:
        """Must be sent on a DIFFERENT connection than the one running the scan."""
        self.ensure_auth()
        with self._txn("turbo cancel", 6.0):
            self._send_packet(CMD_PROC_TURBOSCAN_CANCEL, struct.pack("<I", pid))
            self._expect_success("turbo cancel")


# ----------------------------------------------------------------------------
# Turbo scan session (one per connection; the server frees it on disconnect)
# ----------------------------------------------------------------------------
class ScanCancelled(Exception):
    pass


@dataclass
class ScanResult:
    addr: int
    current: bytes
    previous: bytes
    first: Optional[bytes] = None


class TurboScanSession:
    """Server-resident turbo scan over a dedicated connection.

    first scan:  known value -> START(RESIDENT|SEGMENTS) ; if the server declines
                 (too many results) -> SNAPSHOT + exact COUNT, all server-side.
                 unknown value -> START(SNAPSHOT|SEGMENTS[|KEEP_FIRST|KEEP_PREVIOUS])
    next scan:   COUNT(RESIDENT) narrows in place
    results:     GET(start, count) pages
    """

    def __init__(self, client: PS5DebugClient, caps: TurboCaps) -> None:
        self.c = client
        self.caps = caps
        self.pid = 0
        self.value_type = 4
        self.value_len = 4
        self.count = 0
        self.active = False
        self.mode = ""          # "list" | "snapshot"

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def segments_blob(segments: list[tuple[int, int]]) -> bytes:
        return struct.pack("<I", len(segments)) + b"".join(struct.pack("<QI", a, n) for a, n in segments)

    def _read_progress(self, on_progress: Optional[Callable[[int], None]]) -> None:
        while True:
            v = self.c._recv_u64()
            if v == SENTINEL64:
                return
            if on_progress:
                on_progress(v)

    def end(self) -> None:
        if not self.c.connected:
            self.active = False
            return
        self.c.ensure_auth()
        with self.c._txn("turbo end"):
            self.c._send_packet(CMD_PROC_TURBOSCAN_END)
            self.c._expect_success("turbo end")
        self.active = False
        self.count = 0

    # -- first scan --------------------------------------------------------
    def first_scan(self, pid: int, segments: list[tuple[int, int]], value_type: int, compare: int,
                   value: bytes, mask: Optional[bytes], alignment: int, flags: int,
                   on_progress: Optional[Callable[[str, int, int], None]] = None,
                   keep_first: bool = True, include_zeros: bool = False) -> int:
        """Returns the number of results.  `value` is the encoded scan value
        (low+high for 'between'), `mask` only for array-of-bytes (type 10)."""
        c = self.c
        c.ensure_auth()
        if not segments:
            raise ProtocolError("no memory regions selected")
        self.pid = pid
        self.value_type = value_type
        self.value_len = VALUE_SIZES.get(value_type, len(value) if value_type == 10 else 0)
        if self.value_len == 0:
            raise ProtocolError("bad value type")
        if compare in (11, 12):           # unknown initial value -> snapshot
            if self.value_len > 8:
                raise ProtocolError("unknown-value scans need a 1/2/4/8-byte type")
            return self._snapshot(pid, segments, value_type, compare, alignment, flags,
                                  on_progress, keep_first, include_zeros)
        n = self._resident_start(pid, segments, value_type, compare, value, mask, alignment, flags, on_progress)
        if n is not None:
            return n
        # server declined (more results than its resident cap): snapshot + narrow, still server-side
        if self.value_len > 8:
            raise ProtocolError("too many results for an array-of-bytes scan - make the pattern longer "
                                "or scan fewer regions")
        if on_progress:
            on_progress("too many hits for the fast list - switching to snapshot mode", 0, 0)
        self._snapshot(pid, segments, value_type, 11, alignment, flags, on_progress,
                       keep_first, include_zeros or not any(value))
        return self.next_scan(compare, value, mask, flags, on_progress)

    def _resident_start(self, pid, segments, vt, cmp, value, mask, align, flags, on_progress) -> Optional[int]:
        c = self.c
        f = flags | TS_SERVER_RESIDENT | TS_SNAPSHOT_SEGMENTS
        send_value = cmp in CMP_NEEDS_VALUE
        len_data = len(value) if value else self.value_len
        hdr = struct.pack("<IQIBBBII", pid, segments[0][0], segments[0][1], vt, cmp, align & 0xFF, len_data, f)
        if on_progress:
            total = sum(n for _a, n in segments)
            on_progress(f"scanning {len(segments)} region(s), {total / 1048576:.0f} MB", 0, 0)
        with c._txn("first scan", NO_TIMEOUT):
            c._send_packet(CMD_PROC_TURBOSCAN_START, hdr)
            c._expect_success("first scan")
            sock = c._sock_or_raise()
            if send_value and value:
                sock.sendall(value)
            if vt == 10:
                sock.sendall(mask or b"\x01" * self.value_len)
            c._expect_success("first scan (setup)")
            sock.sendall(self.segments_blob(segments))
            stored, count = struct.unpack("<IQ", c._recv(12))
            if not stored:
                # declined: an empty result stream (sentinel) follows, then SUCCESS
                if c._recv_u64() != SENTINEL64:
                    raise c._broken("first scan: unexpected data after the decline")
                c._expect_success("first scan (end)")
                self.active = False
                return None
            c._expect_success("first scan (end)")
        self.active, self.mode, self.count = True, "list", count
        return count

    def _snapshot(self, pid, segments, vt, cmp, align, flags, on_progress, keep_first, include_zeros) -> int:
        c = self.c
        f = flags | TS_SNAPSHOT | TS_SNAPSHOT_SEGMENTS
        if include_zeros:
            f |= TS_SNAPSHOT_INCLUDE_ZEROS
        if keep_first and self.caps.has(TSE_SNAPSHOT_FIRST):
            f |= TS_SNAPSHOT_KEEP_FIRST
        hdr = struct.pack("<IQIBBBII", pid, segments[0][0], segments[0][1], vt, 11 if cmp not in (11, 12) else cmp,
                          align & 0xFF, 0, f)
        with c._txn("snapshot scan", NO_TIMEOUT):
            c._send_packet(CMD_PROC_TURBOSCAN_START, hdr)
            c._expect_success("snapshot scan")
            c._expect_success("snapshot scan (setup)")
            c._sock_or_raise().sendall(self.segments_blob(segments))
            slots, total = struct.unpack("<QQ", c._recv(16))
            self._read_progress((lambda v: on_progress("snapshot", v, total)) if on_progress else None)
            ok, survivors = struct.unpack("<IQ", c._recv(12))
            c._expect_success("snapshot scan (end)")
        if not ok:
            self.active = False
            raise ProtocolError("the console could not store the snapshot (not enough space, or cancelled). "
                                "Select fewer regions, or set a faster spill drive in Scanner settings.")
        self.active, self.mode, self.count = True, "snapshot", survivors
        self._slots = slots
        return survivors

    # -- next scan ----------------------------------------------------------
    def next_scan(self, compare: int, value: bytes, mask: Optional[bytes], flags: int,
                  on_progress: Optional[Callable[[str, int, int], None]] = None) -> int:
        c = self.c
        if not self.active:
            raise ProtocolError("no scan in progress - press First Scan")
        f = flags | TS_SERVER_RESIDENT
        send_value = compare in CMP_NEEDS_VALUE
        len_data = len(value) if (send_value and value) else self.value_len
        hdr = struct.pack("<IQBBII", self.pid, 0, self.value_type, compare, len_data, f)
        slots = getattr(self, "_slots", 0)
        with c._txn("next scan", NO_TIMEOUT):
            c._send_packet(CMD_PROC_TURBOSCAN_COUNT, hdr)
            c._expect_success("next scan")
            sock = c._sock_or_raise()
            if send_value and value:
                sock.sendall(value)
            if self.value_type == 10:
                sock.sendall(mask or b"\x01" * self.value_len)
            self._read_progress((lambda v: on_progress("rescan", v, slots)) if on_progress else None)
            n = c._recv_u64()
            c._expect_success("next scan (end)")
        self.count = n
        return n

    # -- results -------------------------------------------------------------
    def get_raw(self, start: int, count: int) -> tuple[bytes, int, int]:
        """Results as one blob: -> (blob, number of records, record size).  Record = u64 address,
        then current / previous (/ first) value - parse it in bulk (pointer scan reads millions)."""
        c = self.c
        if not self.active or count <= 0:
            return b"", 0, 8 + 2 * self.value_len
        vl = self.value_len
        with c._txn("get results", 120.0):
            c._send_packet(CMD_PROC_TURBOSCAN_GET, struct.pack("<III", start, count, 0))
            c._expect_success("get results")
            hdr = c._recv_u32()
            n, three = hdr & 0x7FFFFFFF, bool(hdr & 0x80000000)
            rec = 8 + vl * (3 if three else 2)
            blob = c._recv(n * rec)
            c._expect_success("get results (end)")
        return blob, n, rec

    # -- results -------------------------------------------------------------
    def get(self, start: int, count: int) -> list[ScanResult]:
        c = self.c
        if not self.active or count <= 0:
            return []
        vl = self.value_len
        with c._txn("get results", 60.0):
            c._send_packet(CMD_PROC_TURBOSCAN_GET, struct.pack("<III", start, count, 0))
            c._expect_success("get results")
            hdr = c._recv_u32()
            n, three = hdr & 0x7FFFFFFF, bool(hdr & 0x80000000)
            rec = 8 + vl * (3 if three else 2)
            blob = c._recv(n * rec)
            c._expect_success("get results (end)")
        out = []
        for i in range(n):
            o = i * rec
            addr = struct.unpack_from("<Q", blob, o)[0]
            cur = blob[o + 8 : o + 8 + vl]
            prev = blob[o + 8 + vl : o + 8 + 2 * vl]
            first = blob[o + 8 + 2 * vl : o + 8 + 3 * vl] if three else None
            out.append(ScanResult(addr, cur, prev, first))
        return out
