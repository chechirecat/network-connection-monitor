"""Intranet/internet classification and client/server role detection."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

INTRANET = "intranet"
INTERNET = "internet"

# Deliberately not ipaddress.is_private: that also counts documentation and
# other special-purpose ranges, which are not "my local network".
_LOCAL_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",  # CGNAT / Tailscale-style VPN ranges
        "0.0.0.0/8",
        "224.0.0.0/4",  # multicast
        "255.255.255.255/32",
        "::1/128",
        "::/128",
        "fe80::/10",
        "fc00::/7",
        "ff00::/8",  # multicast
    )
]


class Classifier:
    def __init__(self, extra_local: list[str] | None = None) -> None:
        self.nets = list(_LOCAL_NETS)
        for net in extra_local or []:
            self.nets.append(ipaddress.ip_network(net, strict=False))
        self.is_local = lru_cache(maxsize=65536)(self._is_local)

    def _is_local(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr.version == n.version and addr in n for n in self.nets)

    def scope(self, a: str, b: str) -> str:
        """A pair is intranet only if both endpoints are local."""
        return INTRANET if self.is_local(a) and self.is_local(b) else INTERNET


# Ports that identify the server side of a conversation even when both ports are high.
WELL_KNOWN = {
    20, 21, 22, 23, 25, 53, 67, 69, 80, 110, 123, 137, 138, 139, 143, 161, 389, 443,
    445, 465, 514, 587, 631, 636, 853, 873, 993, 995, 1194, 1433, 1521, 1883, 1900,
    2049, 2375, 2376, 3000, 3306, 3389, 5000, 5060, 5201, 5222, 5353, 5355, 5432,
    5672, 5900, 6379, 6443, 8000, 8008, 8080, 8443, 8883, 8888, 9000, 9090, 9092,
    9200, 9418, 11211, 25565, 27017, 32400, 51820,
}


def _server_score(port: int) -> int:
    if port in WELL_KNOWN:
        return 3
    if port < 1024:
        return 2
    if port < 32768:
        return 1
    return 0  # ephemeral range


def dst_is_server(sport: int | None, dport: int | None) -> bool:
    """Guess from ports alone whether the destination of a packet is the server."""
    if sport is None or dport is None:
        return True
    s, d = _server_score(sport), _server_score(dport)
    if s != d:
        return d > s
    return dport <= sport
