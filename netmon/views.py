"""Group pair snapshots into server boxes containing their clients."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Iterable

from .geo import LOCAL, region_of
from .model import PairView
from .packets import proto_name

GROUP_HOST = "host"  # one box per server host (all ports merged)
GROUP_SERVICE = "service"  # one box per server host + port + protocol

METRIC_RATE = "rate"
METRIC_TOTAL = "total"

SORT_KEYS = ("size", "name", "clients", "port")

NameLookup = Callable[[str], str | None]


@lru_cache(maxsize=4096)
def service_name(port: int | None, proto: int) -> str:
    if port is None:
        return proto_name(proto)
    try:
        name = socket.getservbyport(port, proto_name(proto))
    except (OSError, OverflowError):
        name = None
    return f"{port}/{name}" if name else f"{port}/{proto_name(proto)}"


@dataclass(slots=True)
class ClientView:
    ip: str
    name: str | None = None
    rate_up: float = 0.0
    rate_down: float = 0.0
    up: int = 0
    down: int = 0
    conns: int = 0
    cc: str | None = None  # country of the remote end of this client's traffic
    remote: str | None = None

    @property
    def region(self) -> str:
        return region_of(self.cc) if self.remote else LOCAL

    @property
    def rate(self) -> float:
        return self.rate_up + self.rate_down

    @property
    def total(self) -> int:
        return self.up + self.down

    @property
    def label(self) -> str:
        return self.name or self.ip


@dataclass(slots=True)
class GroupView:
    scope: str
    server: str
    name: str | None = None
    cc: str | None = None
    server_is_remote: bool = False
    ports: set[tuple[int | None, int]] = field(default_factory=set)  # (port, proto)
    clients: list[ClientView] = field(default_factory=list)

    @property
    def rate_up(self) -> float:
        return sum(c.rate_up for c in self.clients)

    @property
    def rate_down(self) -> float:
        return sum(c.rate_down for c in self.clients)

    @property
    def rate(self) -> float:
        return sum(c.rate for c in self.clients)

    @property
    def total(self) -> int:
        return sum(c.total for c in self.clients)

    @property
    def conns(self) -> int:
        return sum(c.conns for c in self.clients)

    @property
    def label(self) -> str:
        return self.name or self.server

    @property
    def region(self) -> str:
        return region_of(self.cc) if self.server_is_remote else LOCAL

    @property
    def services(self) -> str:
        names = [service_name(p, pr) for p, pr in sorted(self.ports, key=lambda x: (x[0] or -1, x[1]))]
        if len(names) > 4:
            names = names[:4] + [f"+{len(names) - 4}"]
        return ",".join(names)

    @property
    def lowest_port(self) -> int:
        return min((p for p, _ in self.ports if p is not None), default=1 << 17)

    @property
    def protos(self) -> set[int]:
        return {pr for _, pr in self.ports}


def build_groups(
    pairs: Iterable[PairView], mode: str = GROUP_HOST, names: NameLookup | None = None
) -> list[GroupView]:
    names = names or (lambda ip: None)
    groups: dict[tuple, GroupView] = {}
    clients: dict[tuple, ClientView] = {}
    for p in pairs:
        gkey = (p.scope, p.server) if mode == GROUP_HOST else (p.scope, p.server, p.port, p.proto)
        g = groups.get(gkey)
        if g is None:
            g = groups[gkey] = GroupView(scope=p.scope, server=p.server, name=names(p.server))
        if p.remote == p.server:
            g.server_is_remote, g.cc = True, p.remote_cc
        g.ports.add((p.port, p.proto))
        ckey = (gkey, p.client)
        c = clients.get(ckey)
        if c is None:
            c = clients[ckey] = ClientView(ip=p.client, name=names(p.client))
            g.clients.append(c)
        if p.remote:
            c.remote, c.cc = p.remote, p.remote_cc
        c.rate_up += p.rate_up
        c.rate_down += p.rate_down
        c.up += p.up
        c.down += p.down
        c.conns += p.conns
    return list(groups.values())


def weight(item: GroupView | ClientView, metric: str) -> float:
    return item.rate if metric == METRIC_RATE else float(item.total)


def sort_groups(groups: list[GroupView], key: str, metric: str, reverse: bool = False) -> list[GroupView]:
    """Sort groups and the clients inside them. ``reverse`` flips the natural order."""

    def client_key(c: ClientView):
        if key == "name":
            return (c.label.lower(),)
        return (-weight(c, metric), c.label)

    def group_key(g: GroupView):
        if key == "name":
            return (g.label.lower(),)
        if key == "clients":
            return (-len(g.clients), -weight(g, metric))
        if key == "port":
            return (g.lowest_port, -weight(g, metric))
        return (-weight(g, metric), g.label)

    for g in groups:
        g.clients.sort(key=client_key, reverse=reverse)
    return sorted(groups, key=group_key, reverse=reverse)
