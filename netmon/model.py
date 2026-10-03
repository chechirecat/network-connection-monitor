"""Traffic accounting.

Packets are folded into *pairs*: one client host talking to one server
endpoint (server ip, server port, protocol). Capture threads call
``TrafficModel.add``; the UI calls ``TrafficModel.tick`` once per refresh to
update smoothed rates and get an immutable snapshot.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .classify import Classifier, dst_is_server
from .packets import TCP, Packet

PairKey = tuple[str, str, int | None, int]  # client, server, server port, proto
Endpoint = tuple[str, int]  # ip, port (-1 when the protocol has no ports)

MAX_TRACKED_PORTS = 64
HISTORY_TICKS = 120  # rate samples kept per pair for the traffic graph
DUMP_SIZE = 2000  # packets kept for the dump view

# connection states (TCP); other protocols are always ACTIVE
STATE_SYN = "syn"
STATE_SYN_ACK = "syn-ack"
STATE_OPEN = "open"
STATE_CLOSING = "closing"
STATE_CLOSED = "closed"
STATE_RESET = "reset"
STATE_ACTIVE = "active"  # seen without a handshake (capture started mid-connection) or not TCP


@dataclass(slots=True)
class _Conn:
    """One transport connection (5-tuple)."""

    client: Endpoint
    server: Endpoint
    proto: int
    pair: PairKey
    first_seen: float
    last_seen: float
    state: str = STATE_ACTIVE
    fin_up: bool = False
    fin_down: bool = False
    up: int = 0
    down: int = 0
    packets: int = 0
    pend_up: int = 0
    pend_down: int = 0
    rate_up: float = 0.0
    rate_down: float = 0.0

    def update_state(self, p: Packet, is_up: bool) -> None:
        if p.proto != TCP:
            return
        if p.rst:
            self.state = STATE_RESET
        elif p.syn:
            self.state = STATE_SYN_ACK if p.ack else STATE_SYN
        elif p.fin:
            if is_up:
                self.fin_up = True
            else:
                self.fin_down = True
            self.state = STATE_CLOSED if self.fin_up and self.fin_down else STATE_CLOSING
        elif self.state in (STATE_SYN, STATE_SYN_ACK):
            self.state = STATE_OPEN


@dataclass(slots=True, frozen=True)
class ConnView:
    client: str
    client_port: int | None
    server: str
    server_port: int | None
    proto: int
    scope: str
    state: str
    up: int
    down: int
    packets: int
    rate_up: float
    rate_down: float
    first_seen: float
    last_seen: float

    @property
    def rate(self) -> float:
        return self.rate_up + self.rate_down

    @property
    def total(self) -> int:
        return self.up + self.down


@dataclass(slots=True, frozen=True)
class DumpEntry:
    seq: int  # running number, for incremental display
    time: float  # wall clock
    pair: PairKey
    up: bool  # client -> server
    packet: Packet


@dataclass(slots=True)
class _Pair:
    client: str
    server: str
    port: int | None
    proto: int
    scope: str
    remote: str | None  # the non-local endpoint, if any
    first_seen: float
    last_seen: float
    client_ports: set[int] = field(default_factory=set)
    up: int = 0  # bytes client -> server
    down: int = 0  # bytes server -> client
    packets: int = 0
    pend_up: int = 0
    pend_down: int = 0
    rate_up: float = 0.0
    rate_down: float = 0.0
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_TICKS))  # (up, down) per tick


@dataclass(slots=True, frozen=True)
class PairView:
    client: str
    server: str
    port: int | None
    proto: int
    scope: str
    conns: int
    client_ports: frozenset[int]
    up: int
    down: int
    packets: int
    rate_up: float
    rate_down: float
    last_seen: float
    remote: str | None = None
    remote_cc: str | None = None  # country of the remote endpoint
    first_seen: float = 0.0

    @property
    def rate(self) -> float:
        return self.rate_up + self.rate_down

    @property
    def total(self) -> int:
        return self.up + self.down


class TrafficModel:
    def __init__(
        self,
        classifier: Classifier | None = None,
        geo: Callable[[str], str | None] | None = None,
        expire: float = 60.0,
        tau: float = 2.0,
        clock=time.monotonic,
    ) -> None:
        self.classifier = classifier or Classifier()
        self.geo = geo or (lambda ip: None)
        self.expire = expire
        self.tau = tau  # rate smoothing time constant (seconds)
        self.clock = clock
        self._lock = threading.Lock()
        self._pairs: dict[PairKey, _Pair] = {}
        self._conns: dict[tuple, _Conn] = {}  # canonical 5-tuple -> connection
        self._last_tick = clock()
        self.packets = 0
        self.bytes = 0
        # packet dump: only pairs accepted by `watch` are recorded
        self.watch: Callable[[_Pair], bool] | None = None
        self.dump: deque[DumpEntry] = deque(maxlen=DUMP_SIZE)
        self._dump_seq = 0

    def add(self, p: Packet) -> None:
        now = self.clock()
        a = (p.src, -1 if p.sport is None else p.sport)
        b = (p.dst, -1 if p.dport is None else p.dport)
        canon = (p.proto, *(a + b if a <= b else b + a))
        with self._lock:
            self.packets += 1
            self.bytes += p.length
            conn = self._conns.get(canon)
            if conn is None or (p.proto == TCP and p.syn and not p.ack and conn.client != a):
                # new connection, or a new SYN reusing the 5-tuple from the other side
                client = self._guess_client(p, a, b)
                server = b if client == a else a
                key: PairKey = (client[0], server[0], None if server[1] < 0 else server[1], p.proto)
                conn = self._conns[canon] = _Conn(client, server, p.proto, key, now, now)
            conn.last_seen = now
            client = conn.client
            is_up = client == a
            key = conn.pair
            conn.update_state(p, is_up)
            conn.packets += 1
            if is_up:
                conn.up += p.length
                conn.pend_up += p.length
            else:
                conn.down += p.length
                conn.pend_down += p.length
            pair = self._pairs.get(key)
            if pair is None:
                local = self.classifier.is_local
                remote = key[1] if not local(key[1]) else (key[0] if not local(key[0]) else None)
                pair = self._pairs[key] = _Pair(
                    client=key[0],
                    server=key[1],
                    port=key[2],
                    proto=p.proto,
                    scope=self.classifier.scope(key[0], key[1]),
                    remote=remote,
                    first_seen=now,
                    last_seen=now,
                )
            pair.last_seen = now
            pair.packets += 1
            if client[1] >= 0 and len(pair.client_ports) < MAX_TRACKED_PORTS:
                pair.client_ports.add(client[1])
            if is_up:
                pair.up += p.length
                pair.pend_up += p.length
            else:
                pair.down += p.length
                pair.pend_down += p.length
            if self.watch is not None and self.watch(pair):
                self._dump_seq += 1
                self.dump.append(DumpEntry(self._dump_seq, time.time(), key, is_up, p))

    @staticmethod
    def _guess_client(p: Packet, a, b):
        if p.proto == TCP and p.syn:
            return b if p.ack else a  # SYN+ACK comes from the server
        return a if dst_is_server(p.sport, p.dport) else b

    def tick(self) -> list[PairView]:
        """Update smoothed rates, expire idle pairs, return a snapshot."""
        now = self.clock()
        with self._lock:
            dt = max(now - self._last_tick, 1e-3)
            self._last_tick = now
            alpha = 1.0 - math.exp(-dt / self.tau)
            cutoff = now - self.expire
            dead = []
            views = []
            for key, pr in self._pairs.items():
                pr.history.append((pr.pend_up / dt, pr.pend_down / dt))  # unsmoothed, for the graph
                pr.rate_up, pr.rate_down, pr.pend_up, pr.pend_down = _smooth(pr, alpha, dt)
                if pr.last_seen < cutoff:
                    dead.append(key)
                    continue
                views.append(
                    PairView(
                        client=pr.client,
                        server=pr.server,
                        port=pr.port,
                        proto=pr.proto,
                        scope=pr.scope,
                        conns=max(1, len(pr.client_ports)),
                        client_ports=frozenset(pr.client_ports),
                        up=pr.up,
                        down=pr.down,
                        packets=pr.packets,
                        rate_up=pr.rate_up,
                        rate_down=pr.rate_down,
                        last_seen=pr.last_seen,
                        remote=pr.remote,
                        remote_cc=self.geo(pr.remote) if pr.remote else None,
                        first_seen=pr.first_seen,
                    )
                )
            for key in dead:
                del self._pairs[key]
            dead_conns = []
            for canon, c in self._conns.items():
                c.rate_up, c.rate_down, c.pend_up, c.pend_down = _smooth(c, alpha, dt)
                if c.last_seen < cutoff:
                    dead_conns.append(canon)
            for canon in dead_conns:
                del self._conns[canon]
        return views

    # -- detail queries for the zoomed-in views ----------------------------
    def connections(self, match: Callable[[_Pair], bool]) -> list[ConnView]:
        """Connections of all pairs accepted by ``match`` (e.g. ``Focus.matches``)."""
        with self._lock:
            return [
                ConnView(
                    client=c.client[0],
                    client_port=None if c.client[1] < 0 else c.client[1],
                    server=c.server[0],
                    server_port=None if c.server[1] < 0 else c.server[1],
                    proto=c.proto,
                    scope=self._pairs[c.pair].scope,
                    state=c.state,
                    up=c.up,
                    down=c.down,
                    packets=c.packets,
                    rate_up=c.rate_up,
                    rate_down=c.rate_down,
                    first_seen=c.first_seen,
                    last_seen=c.last_seen,
                )
                for c in self._conns.values()
                if c.pair in self._pairs and match(self._pairs[c.pair])
            ]

    def history(self, match: Callable[[_Pair], bool]) -> list[tuple[float, float]]:
        """Summed (up, down) bytes/s per tick of the matching pairs, oldest first."""
        with self._lock:
            hists = [list(pr.history) for pr in self._pairs.values() if match(pr)]
        n = max((len(h) for h in hists), default=0)
        total = [[0.0, 0.0] for _ in range(n)]
        for h in hists:
            for i, (u, d) in enumerate(h, start=n - len(h)):  # align on the newest sample
                total[i][0] += u
                total[i][1] += d
        return [tuple(x) for x in total]

    def set_watch(self, watch: Callable[[_Pair], bool] | None) -> None:
        """Start recording packets of matching pairs for the dump (None stops); clears the dump."""
        with self._lock:
            self.watch = watch
            self.dump.clear()

    def dump_since(self, seq: int) -> list[DumpEntry]:
        with self._lock:
            return [e for e in self.dump if e.seq > seq]

    def reset_totals(self) -> None:
        with self._lock:
            for pr in list(self._pairs.values()) + list(self._conns.values()):
                pr.up = pr.down = pr.packets = 0


def _smooth(x, alpha: float, dt: float) -> tuple[float, float, int, int]:
    """EMA-update rates from pending bytes; returns (rate_up, rate_down, 0, 0)."""
    up = x.rate_up + alpha * (x.pend_up / dt - x.rate_up)
    down = x.rate_down + alpha * (x.pend_down / dt - x.rate_down)
    return (up if up >= 1.0 else 0.0), (down if down >= 1.0 else 0.0), 0, 0
