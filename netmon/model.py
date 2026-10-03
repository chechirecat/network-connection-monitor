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
from dataclasses import dataclass, field
from typing import Callable

from .classify import Classifier, dst_is_server
from .packets import TCP, Packet

PairKey = tuple[str, str, int | None, int]  # client, server, server port, proto

MAX_TRACKED_PORTS = 64


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
        # canonical 5-tuple -> (client endpoint, last seen)
        self._flows: dict[tuple, list] = {}
        self._last_tick = clock()
        self.packets = 0
        self.bytes = 0

    def add(self, p: Packet) -> None:
        now = self.clock()
        a = (p.src, -1 if p.sport is None else p.sport)
        b = (p.dst, -1 if p.dport is None else p.dport)
        canon = (p.proto, *(a + b if a <= b else b + a))
        with self._lock:
            self.packets += 1
            self.bytes += p.length
            flow = self._flows.get(canon)
            if flow is None:
                client = self._guess_client(p, a, b)
                flow = self._flows[canon] = [client, now]
            else:
                flow[1] = now
                if p.proto == TCP and p.syn and not p.ack and flow[0] != a:
                    flow[0] = a  # new connection reusing the 5-tuple; trust the SYN
            client = flow[0]
            is_up = client == a
            server = b if is_up else a
            key: PairKey = (client[0], server[0], None if server[1] < 0 else server[1], p.proto)
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
                pr.rate_up += alpha * (pr.pend_up / dt - pr.rate_up)
                pr.rate_down += alpha * (pr.pend_down / dt - pr.rate_down)
                pr.pend_up = pr.pend_down = 0
                if pr.rate_up < 1.0:
                    pr.rate_up = 0.0
                if pr.rate_down < 1.0:
                    pr.rate_down = 0.0
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
            for canon in [c for c, f in self._flows.items() if f[1] < cutoff]:
                del self._flows[canon]
        return views

    def reset_totals(self) -> None:
        with self._lock:
            for pr in self._pairs.values():
                pr.up = pr.down = pr.packets = 0
