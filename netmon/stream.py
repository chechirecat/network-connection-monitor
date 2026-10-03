"""Follow one connection and reassemble its payload (Wireshark's "Follow TCP stream").

TCP: each direction is a byte stream; a segment's sequence number says where
its payload belongs. Segments are placed by sequence number (relative to the
first one seen, modulo 2^32), out-of-order segments are held until the hole
before them is filled or a timeout declares a gap, and retransmitted bytes are
counted but not repeated. UDP and other protocols are shown datagram by
datagram.

Payload is only collected for the followed connection, only while the stream
view is open, and at most ``MAX_BYTES`` per direction.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .packets import TCP, Packet

MAX_BYTES = 1 << 20  # stored payload per direction
GAP_TIMEOUT = 1.0  # seconds an out-of-order segment waits before the hole is declared a gap
MAX_HELD = 256 * 1024  # out-of-order bytes held per direction before giving up on the hole
SEQ_MOD = 1 << 32
MAX_CHUNKS = 50_000

KIND_DATA = "data"
KIND_GAP = "gap"
KIND_RETRANS = "retransmission"
KIND_EVENT = "event"  # SYN/FIN/RST and other flag-only notes


@dataclass(slots=True)
class Chunk:
    """One piece of the conversation, in the order it became readable."""

    seq: int  # running number for incremental display
    time: float
    up: bool  # client -> server
    kind: str
    offset: int  # relative stream offset (TCP) or datagram number (other)
    data: bytes = b""
    size: int = 0  # gap / retransmission size; len(data) for data

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass
class _Direction:
    base: int | None = None  # absolute seq of relative offset 0
    next: int = 0  # next expected relative offset
    held: dict[int, tuple[bytes, float]] = field(default_factory=dict)  # offset -> (data, arrival)
    stored: int = 0
    received: int = 0  # unique payload bytes
    retrans: int = 0  # duplicate bytes
    gaps: int = 0  # missing bytes
    out_of_order: int = 0  # segments that arrived early
    syn_seen: bool = False
    truncated: bool = False  # MAX_BYTES reached
    ranges: list[tuple[int, int, str]] = field(default_factory=list)  # (start, end, kind) for the overview bar

    def add_range(self, start: int, end: int, kind: str) -> None:
        if self.ranges and self.ranges[-1][2] == kind and self.ranges[-1][1] == start:
            self.ranges[-1] = (self.ranges[-1][0], end, kind)
        else:
            self.ranges.append((start, end, kind))


class StreamFollower:
    """Thread-safe: ``observe`` runs in the capture thread, the rest in the UI."""

    def __init__(self, clock=time.time) -> None:
        self.clock = clock
        self._lock = threading.Lock()
        self.target: tuple[str, int | None, str, int | None, int] | None = None  # client, cport, server, sport, proto
        self._reset()

    def _reset(self) -> None:
        self.chunks: list[Chunk] = []
        self._seq = 0
        self.dirs = {True: _Direction(), False: _Direction()}
        self.started = self.clock()
        self.mid_stream = False  # True when the connection was already running (no SYN seen)

    # -- control (UI) ------------------------------------------------------------
    def follow(self, client: str, cport: int | None, server: str, sport: int | None, proto: int) -> None:
        with self._lock:
            self.target = (client, cport, server, sport, proto)
            self._reset()

    def stop(self) -> None:
        with self._lock:
            self.target = None
            self._reset()

    def wants_payload(self, src: str, sport: int, dst: str, dport: int) -> bool:
        """Asked by the packet parser: keep this packet's full payload?"""
        t = self.target
        if t is None:
            return False
        return (src, sport, dst, dport) in ((t[0], t[1], t[2], t[3]), (t[2], t[3], t[0], t[1]))

    def chunks_since(self, seq: int) -> list[Chunk]:
        with self._lock:
            return [c for c in self.chunks if c.seq > seq]

    def flush(self) -> None:
        """Declare gaps for holes that have waited too long (call regularly)."""
        now = self.clock()
        with self._lock:
            for up, d in self.dirs.items():
                if d.held and min(t for _, t in d.held.values()) < now - GAP_TIMEOUT:
                    self._skip_to_held(up, d, now)

    # -- capture side ----------------------------------------------------------------
    def observe(self, p: Packet) -> None:
        t = self.target
        if t is None or p.proto != t[4]:
            return
        if (p.src, p.sport, p.dst, p.dport) == (t[0], t[1], t[2], t[3]):
            up = True
        elif (p.src, p.sport, p.dst, p.dport) == (t[2], t[3], t[0], t[1]):
            up = False
        else:
            return
        now = self.clock()
        with self._lock:
            if p.proto == TCP and p.seq is not None:
                self._observe_tcp(p, up, now)
            elif p.payload:
                d = self.dirs[up]
                n = d.next
                d.next += 1
                d.received += len(p.payload)
                self._store(up, d, KIND_DATA, n, p.payload, now)

    def _observe_tcp(self, p: Packet, up: bool, now: float) -> None:
        d = self.dirs[up]
        if p.syn:
            d.base = (p.seq + 1) % SEQ_MOD  # SYN occupies one sequence number
            d.syn_seen = True
            self._event(up, "SYN" + ("+ACK" if p.ack else ""), now)
            return
        data = p.payload
        if d.base is None:
            d.base = p.seq
            self.mid_stream = True
        rel = (p.seq - d.base) % SEQ_MOD
        if rel > SEQ_MOD // 2:
            rel -= SEQ_MOD  # before the start we know (e.g. retransmission of older data)
        if data:
            self._place(up, d, rel, data, now)
        if p.fin:
            self._event(up, "FIN", now)
        if p.rst:
            self._event(up, "RST", now)

    def _place(self, up: bool, d: _Direction, rel: int, data: bytes, now: float) -> None:
        end = rel + len(data)
        if end <= d.next:
            d.retrans += len(data)
            self._append(Chunk(0, now, up, KIND_RETRANS, rel, size=len(data)))
            return
        if rel < d.next:  # partly old: keep only the new tail
            d.retrans += d.next - rel
            data = data[d.next - rel :]
            rel = d.next
        if rel > d.next:
            if rel not in d.held:
                d.out_of_order += 1
                d.held[rel] = (data, now)
            if sum(len(x) for x, _ in d.held.values()) > MAX_HELD:
                self._skip_to_held(up, d, now)
            return
        self._accept(up, d, data, now)
        self._drain(up, d, now)

    def _accept(self, up: bool, d: _Direction, data: bytes, now: float) -> None:
        start = d.next
        d.next += len(data)
        d.received += len(data)
        d.add_range(start, d.next, KIND_DATA)
        self._store(up, d, KIND_DATA, start, data, now)

    def _drain(self, up: bool, d: _Direction, now: float) -> None:
        while d.held:
            rel = min(d.held)
            if rel > d.next:
                return
            data, _ = d.held.pop(rel)
            if rel + len(data) <= d.next:
                d.retrans += len(data)
                continue
            self._accept(up, d, data[d.next - rel :], now)

    def _skip_to_held(self, up: bool, d: _Direction, now: float) -> None:
        """Give up waiting: record the hole before the earliest held segment as a gap."""
        rel = min(d.held)
        if rel > d.next:
            size = rel - d.next
            d.gaps += size
            d.add_range(d.next, rel, KIND_GAP)
            self._append(Chunk(0, now, up, KIND_GAP, d.next, size=size))
            d.next = rel
        self._drain(up, d, now)

    def _store(self, up: bool, d: _Direction, kind: str, offset: int, data: bytes, now: float) -> None:
        room = MAX_BYTES - d.stored
        if room <= 0:
            if not d.truncated:
                d.truncated = True
                self._event(up, f"capture limit of {MAX_BYTES // 1024} KiB reached — later data not stored", now)
            return
        data = data[:room]
        d.stored += len(data)
        self._append(Chunk(0, now, up, kind, offset, data, len(data)))

    def _event(self, up: bool, text: str, now: float) -> None:
        self._append(Chunk(0, now, up, KIND_EVENT, self.dirs[up].next, text.encode()))

    def _append(self, c: Chunk) -> None:
        if len(self.chunks) >= MAX_CHUNKS:
            return  # counters keep running; the display list is bounded
        self._seq += 1
        c.seq = self._seq
        self.chunks.append(c)
