#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Regression driver for the pointer-scan command (0xBDAACC30).

Starts ./harness (host build of ptr_scan.c + ptr_scan_core.c, see harness.c) once per case,
talks to it through PS5DebugClient.ptrscan_level(), and checks the results.

All memory images are generated here at run time, so there are no binary fixtures to check in.

    python3 test_ptrscan.py            # all cases
    python3 test_ptrscan.py -v         # verbose
    python3 test_ptrscan.py Cancel     # only cases whose name contains "Cancel"

Environment:
    HARNESS            path to the harness binary          (default: ./harness next to this file)
    PS5DEBUG_CLIENT    path to ps5debug_client.py          (default: searched for in the parent dirs)
"""
from __future__ import annotations

import importlib.util
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.environ.get("HARNESS") or os.path.join(HERE, "harness")


# --------------------------------------------------------------------------------------
# locate + import the client library
# --------------------------------------------------------------------------------------
def _find_client() -> str:
    env = os.environ.get("PS5DEBUG_CLIENT")
    if env:
        return env
    d = HERE
    for _ in range(5):                       # this dir, then up to 4 parents (and their direct subdirs)
        cand = [os.path.join(d, "ps5debug_client.py")]
        try:
            for sub in sorted(os.listdir(d)):
                p = os.path.join(d, sub)
                if os.path.isdir(p) and not sub.startswith("."):
                    cand.append(os.path.join(p, "ps5debug_client.py"))
        except OSError:
            pass
        for c in cand:
            if os.path.isfile(c):
                return c
        d = os.path.dirname(d)
    sys.exit("test_ptrscan: cannot find ps5debug_client.py; set PS5DEBUG_CLIENT=/path/to/it")


def _load_client():
    path = _find_client()
    spec = importlib.util.spec_from_file_location("ps5debug_client", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ps5debug_client"] = mod     # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


C = _load_client()

# --------------------------------------------------------------------------------------
# harness process wrapper
# --------------------------------------------------------------------------------------
PID = 1            # harness treats SIGUSR1 as a cancel for pid 1
CHUNK = 0x100000   # PS_CHUNK in ptr_scan.c
PAGE = 0x1000      # PS_PAGE: retry granularity after a failed chunk read
HDR = "<IIQII"     # struct cmd_proc_ptrscan_packet: pid, flags, max_off, nseg, nfront
FILLER = 0xDEADBEEFDEADBEEF   # larger than any frontier address used below -> never a hit


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Harness:
    """One harness process.  Collects its 'HANDLER rc=.. ms=.. reads_failed=..' lines."""

    def __init__(self, *args: str) -> None:
        self.port = _free_port()
        self.proc = subprocess.Popen([HARNESS, str(self.port), *args], stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.handler_lines: list[dict[str, int]] = []
        self._cv = threading.Condition()
        ready = self.proc.stdout.readline().strip()
        if ready != "ready":
            self.stop()
            raise RuntimeError(f"harness did not start (got {ready!r}; exit={self.proc.poll()})")
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            if line.startswith("HANDLER "):
                kv = dict(p.split("=") for p in line.split()[1:])
                with self._cv:
                    self.handler_lines.append({k: int(v) for k, v in kv.items()})
                    self._cv.notify_all()

    def wait_handler(self, n: int, timeout: float = 10.0) -> dict[str, int]:
        """Block until the n-th HANDLER line (1-based) has been printed and return it."""
        end = time.time() + timeout
        with self._cv:
            while len(self.handler_lines) < n:
                left = end - time.time()
                if left <= 0:
                    raise AssertionError(f"harness printed {len(self.handler_lines)} HANDLER lines, wanted {n}")
                self._cv.wait(left)
            return self.handler_lines[n - 1]

    def client(self):
        cli = C.PS5DebugClient()
        cli.connect("127.0.0.1", self.port, timeout=5.0)
        cli.authed = True            # the harness only implements 0xBDAACC30; skip the auth handshake
        return cli

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()


def write_image(path: str, base: int, words: dict[int, int], nbytes: int, filler: int = FILLER) -> None:
    """--image file: u64 base, then nbytes of memory (every slot = filler except `words`: slot_index -> value)."""
    buf = bytearray(struct.pack("<Q", filler) * (nbytes // 8))
    for idx, val in words.items():
        struct.pack_into("<Q", buf, idx * 8, val)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", base))
        f.write(buf)


def frontier_blob(addrs) -> bytes:
    return b"".join(struct.pack("<Q", a) for a in sorted(addrs))


def records(blob: bytes) -> set[tuple[int, int]]:
    return set(struct.iter_unpack("<QQ", blob))


# --------------------------------------------------------------------------------------
class PtrScanCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._harnesses: list[Harness] = []
        self._clients = []

    def tearDown(self) -> None:
        for c in self._clients:
            c.close()
        for h in self._harnesses:
            h.stop()

    def start(self, *args: str):
        h = Harness(*args)
        self._harnesses.append(h)
        cli = h.client()
        self._clients.append(cli)
        return h, cli

    def raw_request(self, cli, pid=PID, flags=0, max_off=0x10, nseg=1, nfront=1):
        """Send just the 24-byte request header (no segments / frontier) and return the first status word."""
        body = struct.pack(HDR, pid, flags, max_off, nseg, nfront)
        cli.send_cmd(C.CMD_PROC_PTRSCAN, body)
        return cli._recv_status()

    def image(self, base: int, words: dict[int, int], nbytes: int) -> str:
        p = os.path.join(self._tmp.name, f"img{len(os.listdir(self._tmp.name))}.bin")
        write_image(p, base, words, nbytes)
        return p


class TestImage(PtrScanCase):
    BASE = 0x10000000
    SIZE = 0x10000
    F = [0x70000000, 0x70001000, 0x80000000]
    MAXOFF = 0x100

    def scan(self, cli, segs, front=None, max_off=None, **kw):
        return cli.ptrscan_level(PID, segs, frontier_blob(self.F if front is None else front),
                                 self.MAXOFF if max_off is None else max_off, alias=kw.pop("alias", False), **kw)

    def test_range_edges(self):
        """f-max_off <= v <= f is a hit; one past either end is not."""
        f0, f1, f2 = self.F
        hit_vals = {10: f0, 11: f0 - self.MAXOFF, 12: f0 - 0x80, 13: f1 - 1, 14: f2 - 0x40, 15: f1 - self.MAXOFF}
        miss_vals = {20: f0 - self.MAXOFF - 1, 21: f0 + 1, 22: f1 - self.MAXOFF - 1, 23: f2 + 1, 24: 0}
        h, cli = self.start("--image", self.image(self.BASE, {**hit_vals, **miss_vals}, self.SIZE))
        blob, total, scanned, status = self.scan(cli, [(self.BASE, self.SIZE)])
        want = {(self.BASE + i * 8, v) for i, v in hit_vals.items()}
        self.assertEqual(status, 0)
        self.assertEqual(records(blob), want)
        self.assertEqual(total, len(want))
        self.assertEqual(scanned, self.SIZE)
        self.assertEqual(cli.last_ptrscan_unreadable, 0)
        self.assertEqual(h.wait_handler(1)["rc"], 0)

    def test_max_off_zero(self):
        """max_off == 0: only exact frontier addresses match."""
        words = {1: self.F[0], 2: self.F[0] - 1, 3: self.F[1]}
        h, cli = self.start("--image", self.image(self.BASE, words, self.SIZE))
        blob, total, scanned, status = self.scan(cli, [(self.BASE, self.SIZE)], max_off=0)
        self.assertEqual(records(blob), {(self.BASE + 8, self.F[0]), (self.BASE + 24, self.F[1])})

    def test_alias_flag_falls_back_to_plain_reads(self):
        """The harness has no aliasing (scan_alias_begin -> NULL); alias=True must give identical results."""
        words = {5: self.F[0], 6: self.F[1] - 8}
        h, cli = self.start("--image", self.image(self.BASE, words, self.SIZE))
        a = self.scan(cli, [(self.BASE, self.SIZE)], alias=True)
        b = self.scan(cli, [(self.BASE, self.SIZE)], alias=False)
        self.assertEqual(records(a[0]), records(b[0]))
        self.assertEqual(a[1:], b[1:])
        self.assertEqual(len(records(a[0])), 2)

    def test_segments_and_gap(self):
        """Only bytes inside the requested segments are scanned; a pointer in the gap is not reported."""
        words = {0x100 // 8: self.F[0], 0x2800 // 8: self.F[1], 0x4100 // 8: self.F[2] - 8}
        h, cli = self.start("--image", self.image(self.BASE, words, self.SIZE))
        segs = [(self.BASE, 0x2000), (self.BASE + 0x4000, 0x2000)]
        blob, total, scanned, status = self.scan(cli, segs)
        self.assertEqual(status, 0)
        self.assertEqual(records(blob), {(self.BASE + 0x100, self.F[0]), (self.BASE + 0x4100, self.F[2] - 8)})
        self.assertEqual(total, 2)
        self.assertEqual(scanned, 0x4000)

    def test_unaligned_segment(self):
        """Start is rounded up to 8 and a trailing partial slot is ignored: [B+4, B+0x24) covers slots 1..3."""
        words = {i: self.F[0] for i in range(0, 5)}
        h, cli = self.start("--image", self.image(self.BASE, words, self.SIZE))
        blob, total, scanned, status = self.scan(cli, [(self.BASE + 4, 0x20)])
        self.assertEqual(records(blob), {(self.BASE + i * 8, self.F[0]) for i in (1, 2, 3)})
        self.assertEqual(scanned, 0x18)

    def test_tiny_and_empty_segments(self):
        """Segments shorter than a slot (or empty) scan nothing and are not errors."""
        h, cli = self.start("--image", self.image(self.BASE, {0: self.F[0]}, self.SIZE))
        blob, total, scanned, status = self.scan(cli, [(self.BASE, 0), (self.BASE, 7)])
        self.assertEqual((blob, total, scanned, status), (b"", 0, 0, 0))

    def test_chunk_boundary(self):
        """Slots on either side of a 1 MB read-chunk boundary are both found."""
        size = 2 * CHUNK + 0x100
        words = {CHUNK // 8 - 1: self.F[0], CHUNK // 8: self.F[1], 2 * CHUNK // 8 - 1: self.F[2], size // 8 - 1: self.F[0]}
        h, cli = self.start("--image", self.image(self.BASE, words, size))
        blob, total, scanned, status = self.scan(cli, [(self.BASE, size)])
        self.assertEqual(records(blob), {(self.BASE + i * 8, v) for i, v in words.items()})
        self.assertEqual(scanned, size)

    def test_no_hits(self):
        h, cli = self.start("--image", self.image(self.BASE, {}, self.SIZE))
        self.assertEqual(self.scan(cli, [(self.BASE, self.SIZE)]), (b"", 0, self.SIZE, 0))

    def test_repeated_passes_on_one_connection(self):
        """Each pass leaves the connection ready for the next one (no leaked / stale state)."""
        h, cli = self.start("--image", self.image(self.BASE, {3: self.F[0]}, self.SIZE))
        for n in range(1, 6):
            blob, total, scanned, status = self.scan(cli, [(self.BASE, self.SIZE)])
            self.assertEqual((records(blob), total, status), ({(self.BASE + 24, self.F[0])}, 1, 0), f"pass {n}")
            self.assertEqual(h.wait_handler(n)["rc"], 0)


class TestUnreadable(PtrScanCase):
    BASE = 0x10000000

    def test_failed_page_is_skipped_and_counted(self):
        """A read that fails mid-pass (unmapped, process exiting) makes the handler retry the chunk page
        by page: pages that read fine are scanned, the failed page is skipped and counted as unreadable."""
        f = 0x70000000
        b = self.BASE + 0x10000                               # segment B: three pages, the middle one fails
        words = {0x10000 // 8 + 0x10 // 8: f,                 # page 1  -> found
                 0x10000 // 8 + (0x1000 + 0x800) // 8: f,     # page 2  -> lost (read failed)
                 0x10000 // 8 + (0x2000 + 0x20) // 8: f,      # page 3  -> found
                 0x100 // 8: f}                               # segment A -> found
        h, cli = self.start("--image", self.image(self.BASE, words, 0x20000),
                            "--fail", hex(b + 0x1800), hex(b + 0x1810))
        segs = [(self.BASE, 0x1000), (b, 0x3000)]
        blob, total, scanned, status = cli.ptrscan_level(PID, segs, frontier_blob([f]), 0x100, alias=False)
        self.assertEqual(status, 0)
        self.assertEqual(records(blob), {(self.BASE + 0x100, f), (b + 0x10, f), (b + 0x2020, f)})
        self.assertEqual(total, 3)
        self.assertEqual(cli.last_ptrscan_unreadable, PAGE)
        self.assertEqual(scanned, 0x1000 + 0x2000)
        self.assertGreater(h.wait_handler(1)["reads_failed"], 0)
        self.assertEqual(h.wait_handler(1)["rc"], 0)

    def test_unmapped_segment(self):
        """A segment that is entirely unmapped yields no hits and is counted as unreadable, not an error."""
        h, cli = self.start("--image", self.image(self.BASE, {}, 0x1000))
        blob, total, scanned, status = cli.ptrscan_level(PID, [(0x50000000, 0x2000)],
                                                         frontier_blob([0x70000000]), 0x100, alias=False)
        self.assertEqual((blob, total, scanned, status), (b"", 0, 0, 0))
        self.assertEqual(cli.last_ptrscan_unreadable, 0x2000)

    def test_unaligned_failed_piece(self):
        """The retry pieces follow page boundaries, so an unaligned segment loses only the failing page part."""
        f = 0x70000000
        start = self.BASE + 0xC00                              # 0xC00..0x2400: pieces 0x400 / 0x1000 / 0x400
        words = {0xC00 // 8: f, 0x1400 // 8: f, 0x2000 // 8: f}
        h, cli = self.start("--image", self.image(self.BASE, words, 0x10000),
                            "--fail", hex(self.BASE + 0x1000), hex(self.BASE + 0x1008))
        blob, total, scanned, status = cli.ptrscan_level(PID, [(start, 0x1800)], frontier_blob([f]), 0x10, alias=False)
        self.assertEqual(records(blob), {(self.BASE + 0xC00, f), (self.BASE + 0x2000, f)})
        self.assertEqual(cli.last_ptrscan_unreadable, PAGE)


class TestFill(PtrScanCase):
    BASE = 0x10000000

    def test_every_slot_hits_multi_chunk(self):
        """--fill: every slot holds V and V is in the frontier -> every slot is a hit, across several chunks
        and several 256 KB result blocks."""
        size = 3 * CHUNK + 0x2F000                         # not a multiple of the chunk size
        v = 0x70000800
        h, cli = self.start("--fill", hex(self.BASE), hex(size), hex(v))
        blob, total, scanned, status = cli.ptrscan_level(PID, [(self.BASE, size)], frontier_blob([v]), 0x10,
                                                         alias=False)
        self.assertEqual(status, 0)
        self.assertEqual(total, size // 8)
        self.assertEqual(scanned, size)
        self.assertEqual(len(blob), size // 8 * 16)
        self.assertEqual(records(blob), {(self.BASE + i * 8, v) for i in range(size // 8)})

    def test_value_not_in_frontier(self):
        size = 0x100000
        h, cli = self.start("--fill", hex(self.BASE), hex(size), "0x70000800")
        self.assertEqual(cli.ptrscan_level(PID, [(self.BASE, size)], frontier_blob([0x60000000]), 0x100, alias=False),
                         (b"", 0, size, 0))

    def test_large_frontier(self):
        """A frontier much larger than the request header: 20000 addresses, every slot matches one of them."""
        size = 0x10000
        v = 0x70000000 + 5000 * 0x20
        front = [0x70000000 + i * 0x20 for i in range(20000)]
        h, cli = self.start("--fill", hex(self.BASE), hex(size), hex(v))
        blob, total, scanned, status = cli.ptrscan_level(PID, [(self.BASE, size)], frontier_blob(front), 0x10,
                                                         alias=False)
        self.assertEqual((status, total), (0, size // 8))

    def test_many_segments(self):
        """4096 one-page segments: segment table handling and per-segment accounting."""
        v = 0x70000000
        n = 4096
        size = n * 2 * PAGE
        h, cli = self.start("--fill", hex(self.BASE), hex(size), hex(v))
        segs = [(self.BASE + i * 2 * PAGE, PAGE) for i in range(n)]
        blob, total, scanned, status = cli.ptrscan_level(PID, segs, frontier_blob([v]), 0x10, alias=False)
        self.assertEqual((status, total, scanned), (0, n * PAGE // 8, n * PAGE))

    def test_progress_records(self):
        """A progress record is sent every 256 MB: (done, total) with done <= total, total == bytes requested."""
        size = 600 << 20
        h, cli = self.start("--fill", hex(self.BASE), hex(size), hex(FILLER))
        seen: list[tuple[int, int]] = []
        res = cli.ptrscan_level(PID, [(self.BASE, size)], frontier_blob([0x7000]), 0x10, alias=False,
                                on_progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(res, (b"", 0, size, 0))
        self.assertEqual([t for _, t in seen], [size] * len(seen))
        self.assertEqual(len(seen), 2)                    # at 256 MB and 512 MB
        self.assertTrue(all(256 << 20 <= d <= size for d, _ in seen))
        self.assertEqual(sorted(seen), seen)


class TestCancel(PtrScanCase):
    BASE = 0x10000000
    HUGE = 1 << 36                                        # 64 GiB of "memory": far too long to finish

    def test_cancel_stops_pass(self):
        """SIGUSR1 (== 0xBDAACC17 for pid 1) ends a long pass early with status 1 (cancelled), still sending a
        well-formed trailer, and the connection stays usable."""
        h, cli = self.start("--fill", hex(self.BASE), hex(self.HUGE), hex(FILLER))
        timer = threading.Timer(0.5, lambda: os.kill(h.proc.pid, signal.SIGUSR1))
        timer.start()
        t0 = time.time()
        try:
            blob, total, scanned, status = cli.ptrscan_level(PID, [(self.BASE, self.HUGE)], frontier_blob([0x7000]),
                                                             0x10, alias=False)
        finally:
            timer.cancel()
        self.assertEqual(status, 1)
        self.assertLess(time.time() - t0, 30.0)
        self.assertLess(scanned, self.HUGE)
        self.assertEqual(h.wait_handler(1)["rc"], 0)
        blob, total, scanned, status = cli.ptrscan_level(PID, [(self.BASE, 0x10000)], frontier_blob([0x7000]),
                                                         0x10, alias=False)
        self.assertEqual((status, scanned, total), (0, 0x10000, 0))

    def test_stale_cancel_is_dropped(self):
        """A cancel that arrived while idle must not kill the next pass of that pid."""
        h, cli = self.start("--fill", hex(self.BASE), "0x100000", hex(FILLER))
        os.kill(h.proc.pid, signal.SIGUSR1)
        time.sleep(0.2)
        res = cli.ptrscan_level(PID, [(self.BASE, 0x100000)], frontier_blob([0x7000]), 0x10, alias=False)
        self.assertEqual(res, (b"", 0, 0x100000, 0))

    def test_cancel_for_other_pid_is_ignored(self):
        h, cli = self.start("--fill", hex(self.BASE), "0x100000", hex(FILLER))
        os.kill(h.proc.pid, signal.SIGUSR1)               # cancels pid 1 only
        time.sleep(0.2)
        res = cli.ptrscan_level(2, [(self.BASE, 0x100000)], frontier_blob([0x7000]), 0x10, alias=False)
        self.assertEqual(res, (b"", 0, 0x100000, 0))

    def test_client_disconnect_stops_pass(self):
        """Dropping the socket mid-pass ends the pass (handler returns 1 -> client dropped) and the harness
        accepts the next client."""
        h, cli = self.start("--fill", hex(self.BASE), hex(self.HUGE), hex(FILLER))
        sock = cli._sock_or_raise()
        hdr = struct.pack(HDR, PID, 0, 0x10, 1, 1)
        sock.sendall(struct.pack("<III", C.PACKET_MAGIC, C.CMD_PROC_PTRSCAN, len(hdr)) + hdr)
        self.assertEqual(cli._recv_status(), C.STATUS_SUCCESS)
        sock.sendall(struct.pack("<QQ", self.BASE, self.HUGE) + struct.pack("<Q", 0x7000))
        self.assertEqual(cli._recv_status(), C.STATUS_SUCCESS)
        time.sleep(0.2)
        cli.close()
        t0 = time.time()
        self.assertEqual(h.wait_handler(1, timeout=30.0)["rc"], 1)
        self.assertLess(time.time() - t0, 25.0)
        cli2 = h.client()
        self._clients.append(cli2)
        res = cli2.ptrscan_level(PID, [(self.BASE, 0x1000)], frontier_blob([0x7000]), 0x10, alias=False)
        self.assertEqual(res, (b"", 0, 0x1000, 0))


class TestRejects(PtrScanCase):
    """Everything the handler refuses answers CMD_DATA_NULL and keeps the connection (and stream) usable."""
    BASE = 0x10000000

    def start_ok(self):
        h, cli = self.start("--fill", hex(self.BASE), "0x10000", "0x70000000")
        return h, cli

    def assertStillWorks(self, h, cli):
        res = cli.ptrscan_level(PID, [(self.BASE, 0x10000)], frontier_blob([0x70000000]), 0, alias=False)
        self.assertEqual((res[1], res[3]), (0x10000 // 8, 0))

    def test_before_ack(self):
        h, cli = self.start_ok()
        cases = {
            "pid 0": dict(pid=0),
            "unknown flag bit": dict(flags=2),
            "flag bits high": dict(flags=0x80000001),
            "max_off too big": dict(max_off=0x100001),
            "no segments": dict(nseg=0),
            "too many segments": dict(nseg=65537),
            "no frontier": dict(nfront=0),
            "frontier too big": dict(nfront=(8 << 20) + 1),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                self.assertEqual(self.raw_request(cli, **kw), C.STATUS_DATA_NULL)
        with self.subTest("short request"):
            cli.send_cmd(C.CMD_PROC_PTRSCAN, b"\0" * 8)
            self.assertEqual(cli._recv_status(), C.STATUS_DATA_NULL)
        with self.subTest("max_off exactly at the limit is accepted"):
            self.assertEqual(self.raw_request(cli, max_off=0x100000), C.STATUS_SUCCESS)
            cli._sock_or_raise().sendall(struct.pack("<QQ", self.BASE, 0x1000) + struct.pack("<Q", 0x70000000))
            self.assertEqual(cli._recv_status(), C.STATUS_SUCCESS)
            while True:                                   # drain the stream by hand
                n = cli._recv_u32()
                if n == 0:
                    break
                cli._recv(16 if n == 0xFFFFFFFF else n * 16)
            cli._recv(8 + 8 + 8 + 4)
            cli._expect_success("end")
        self.assertStillWorks(h, cli)

    def test_noauth(self):
        h, cli = self.start("--noauth", "--fill", hex(self.BASE), "0x1000", "0")
        with self.assertRaisesRegex(C.ProtocolError, "DATA_NULL"):
            cli.ptrscan_level(PID, [(self.BASE, 0x1000)], frontier_blob([0x7000]), 0x10, alias=False)
        self.assertTrue(cli.connected, "a refused request must not drop the connection")
        self.assertEqual(h.wait_handler(1)["rc"], 0)

    def test_after_ack_bad_inputs(self):
        """Inputs are validated after they have been received, so the stream stays in sync."""
        h, cli = self.start_ok()
        top = 0x800000000000
        bad = {
            "frontier descending": ([(self.BASE, 0x1000)], struct.pack("<QQ", 0x70000010, 0x70000000)),
            "segment wraps": ([(0xFFFFFFFFFFFFF000, 0x2000)], frontier_blob([0x7000])),
            "segment ends above user space": ([(top - 0x1000, 0x2000)], frontier_blob([0x7000])),
            "segment starts in kernel half": ([(0xFFFF800000000000, 0x1000)], frontier_blob([0x7000])),
        }
        for name, (segs, front) in bad.items():
            with self.subTest(name):
                with self.assertRaisesRegex(C.ProtocolError, "DATA_NULL"):
                    cli.ptrscan_level(PID, segs, front, 0x10, alias=False)
                self.assertTrue(cli.connected)
        with self.subTest("segment ending exactly at the top is fine"):
            res = cli.ptrscan_level(PID, [(top - 0x1000, 0x1000)], frontier_blob([0x7000]), 0x10, alias=False)
            self.assertEqual((res[1], res[3]), (0, 0))
        self.assertStillWorks(h, cli)

    def test_unknown_command(self):
        h, cli = self.start_ok()
        cli.send_cmd(0xBDAACC31, b"")
        self.assertEqual(cli._recv_status(), C.STATUS_ERROR)
        self.assertStillWorks(h, cli)


if __name__ == "__main__":
    if not os.access(HARNESS, os.X_OK):
        sys.exit(f"test_ptrscan: {HARNESS} not found - run `make harness` first")
    unittest.main(verbosity=1)
