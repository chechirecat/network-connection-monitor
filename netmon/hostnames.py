"""Learn hostnames from traffic: TLS ClientHello SNI and plain DNS answers.

Encrypted connections still announce the site name in the first TLS message
(the ClientHello's server_name extension), and most DNS lookups travel in
plain text. Both reveal which service sits behind a shared IP (CDNs such as
Cloudflare serve many sites from one address).

Limits: QUIC/HTTP3 (UDP 443) encrypts its ClientHello, DNS over HTTPS/TLS is
invisible, and Encrypted Client Hello (ECH) replaces the SNI with a decoy
(``cloudflare-ech.com``), which is recorded but ranked below DNS names.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from .packets import TCP, UDP, Packet

SOURCE_SNI = "TLS SNI"
SOURCE_DNS = "DNS"
SOURCE_ECH = "TLS ECH (decoy)"
SOURCE_PTR = "reverse DNS"
# lower = more trustworthy for labelling a server
_RANK = {SOURCE_SNI: 0, SOURCE_DNS: 1, SOURCE_ECH: 2, SOURCE_PTR: 3}

SNIFF_LIMIT = 16384  # bytes of a ClientHello we are willing to collect
MAX_IPS = 50_000
MAX_NAMES_PER_IP = 20
MAX_PENDING = 4096

FlowKey = tuple[str, int, str, int]  # src, sport, dst, dport (client -> server)


@dataclass(slots=True)
class NameInfo:
    name: str
    source: str
    count: int
    last_seen: float


@dataclass(slots=True)
class TlsHello:
    sni: str | None
    alpn: list[str]
    ech: bool


def parse_client_hello(data: bytes) -> TlsHello | None:
    """Parse a TLS ClientHello from the start of a TLS record stream.
    Returns None if ``data`` is not a ClientHello or is incomplete."""
    try:
        if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
            return None
        (rec_len,) = struct.unpack_from("!H", data, 3)
        hs_len = int.from_bytes(data[6:9], "big")
        body = data[9 : 9 + hs_len]
        if len(body) < hs_len or rec_len < 4:
            return None
        off = 2 + 32  # client_version, random
        off += 1 + body[off]  # session id
        (n,) = struct.unpack_from("!H", body, off)
        off += 2 + n  # cipher suites
        off += 1 + body[off]  # compression methods
        if off + 2 > len(body):
            return TlsHello(None, [], False)  # no extensions
        (ext_total,) = struct.unpack_from("!H", body, off)
        off += 2
        end = min(off + ext_total, len(body))
        sni, alpn, ech = None, [], False
        while off + 4 <= end:
            etype, elen = struct.unpack_from("!HH", body, off)
            ext = body[off + 4 : off + 4 + elen]
            off += 4 + elen
            if etype == 0x0000 and len(ext) >= 5:  # server_name
                name_type, name_len = ext[2], struct.unpack_from("!H", ext, 3)[0]
                if name_type == 0:
                    sni = ext[5 : 5 + name_len].decode("ascii", "replace").lower()
            elif etype == 0x0010 and len(ext) >= 2:  # ALPN
                i = 2
                while i < len(ext):
                    n = ext[i]
                    alpn.append(ext[i + 1 : i + 1 + n].decode("ascii", "replace"))
                    i += 1 + n
            elif etype == 0xFE0D:  # encrypted_client_hello
                ech = True
        return TlsHello(sni, alpn, ech)
    except (IndexError, struct.error):
        return None


def _hello_length(data: bytes) -> int | None:
    """Bytes needed for the complete first handshake message, if this looks like a ClientHello."""
    if len(data) >= 9 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01:
        return 9 + int.from_bytes(data[6:9], "big")
    return None


def _dns_name(msg: bytes, off: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name; returns (name, offset after it)."""
    labels, jumped, end = [], False, off
    for _ in range(64):  # loop guard against malicious pointers
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((n & 0x3F) << 8) | msg[off + 1]
            jumped = True
            continue
        off += 1
        if n == 0:
            break
        labels.append(msg[off : off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels).lower(), (end if jumped else off)


def parse_dns_answers(msg: bytes) -> list[tuple[str, str]]:
    """(ip, queried name) for every A/AAAA record in a DNS response."""
    try:
        if len(msg) < 12 or not msg[2] & 0x80:  # must be a response
            return []
        qd, an = struct.unpack_from("!HH", msg, 4)
        off = 12
        question = None
        for _ in range(qd):
            name, off = _dns_name(msg, off)
            question = question or name
            off += 4
        out = []
        for _ in range(an):
            name, off = _dns_name(msg, off)
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
            off += 10
            rdata = msg[off : off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                out.append((socket.inet_ntop(socket.AF_INET, rdata), question or name))
            elif rtype == 28 and rdlen == 16:
                out.append((socket.inet_ntop(socket.AF_INET6, rdata), question or name))
        return out
    except (IndexError, struct.error, ValueError):
        return []


class HostNames:
    """Thread-safe store of names learned per IP, fed by ``observe`` from the capture thread."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._lock = threading.Lock()
        self._names: OrderedDict[str, dict[str, NameInfo]] = OrderedDict()
        self._conn_sni: OrderedDict[FlowKey, TlsHello] = OrderedDict()
        # flows whose ClientHello spans several TCP segments: key -> (next seq, bytes so far)
        self.pending: dict[FlowKey, tuple[int | None, bytes]] = {}

    # -- capture side ------------------------------------------------------
    def wants_payload(self, src: str, sport: int, dst: str, dport: int) -> bool:
        """Asked by the packet parser: keep this segment's payload (continuation of a ClientHello)?"""
        return (src, sport, dst, dport) in self.pending

    def observe(self, p: Packet) -> None:
        if not self.enabled or not p.payload:
            return
        if p.proto == TCP:
            self._observe_tls(p)
        elif p.proto == UDP and p.sport == 53:
            for ip, name in parse_dns_answers(p.payload):
                self.add(ip, name, SOURCE_DNS)

    def _observe_tls(self, p: Packet) -> None:
        key = (p.src, p.sport, p.dst, p.dport)
        with self._lock:
            pend = self.pending.pop(key, None)
        if pend is not None:
            next_seq, buf = pend
            if next_seq is not None and p.seq is not None and p.seq != next_seq:
                return  # out of order or retransmission: give up on this hello
            data = buf + p.payload
        elif _hello_length(p.payload) is not None:
            data = p.payload
        else:
            return
        need = _hello_length(data)
        if need is None:
            return
        if len(data) < need:
            if len(data) < SNIFF_LIMIT and len(self.pending) < MAX_PENDING:
                nxt = (p.seq + len(p.payload)) & 0xFFFFFFFF if p.seq is not None else None
                with self._lock:
                    self.pending[key] = (nxt, data)
            return
        hello = parse_client_hello(data)
        if hello is None:
            return
        with self._lock:
            self._conn_sni[key] = hello
            if len(self._conn_sni) > MAX_IPS:
                self._conn_sni.popitem(last=False)
        if hello.sni:
            self.add(p.dst, hello.sni, SOURCE_ECH if hello.ech else SOURCE_SNI)

    def add(self, ip: str, name: str, source: str) -> None:
        now = time.time()
        with self._lock:
            names = self._names.get(ip)
            if names is None:
                names = self._names[ip] = {}
                if len(self._names) > MAX_IPS:
                    self._names.popitem(last=False)
            else:
                self._names.move_to_end(ip)
            info = names.get(name)
            if info is None:
                if len(names) >= MAX_NAMES_PER_IP:
                    del names[min(names, key=lambda n: names[n].last_seen)]
                names[name] = NameInfo(name, source, 1, now)
            else:
                info.count += 1
                info.last_seen = now
                if _RANK[source] < _RANK[info.source]:
                    info.source = source

    # -- UI side -------------------------------------------------------------
    def names(self, ip: str) -> list[NameInfo]:
        """Everything learned for ``ip``, most trustworthy and most used first."""
        with self._lock:
            infos = list(self._names.get(ip, {}).values())
        return sorted(infos, key=lambda i: (_RANK[i.source], -i.count, -i.last_seen))

    def best(self, ip: str) -> str | None:
        """Label for ``ip``: best name, with "+N" when several sites share the address."""
        infos = [i for i in self.names(ip) if i.source != SOURCE_ECH] or self.names(ip)
        if not infos:
            return None
        extra = len(infos) - 1
        return infos[0].name + (f" +{extra}" if extra else "")

    def connection(self, client: str, cport: int | None, server: str, sport: int | None) -> TlsHello | None:
        with self._lock:
            return self._conn_sni.get((client, cport, server, sport))


# -- builders, used by the demo source and tests ------------------------------------
def build_client_hello(sni: str | None, alpn: tuple[str, ...] = ("h2", "http/1.1"), ech: bool = False,
                       padding: int = 0) -> bytes:
    """A minimal but well-formed TLS 1.3-style ClientHello record."""
    exts = b""
    if padding:  # e.g. a big key_share placed before the SNI, as Chrome may do
        exts += struct.pack("!HH", 0x0015, padding) + bytes(padding)
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += struct.pack("!HHH", 0x0000, len(entry) + 2, len(entry)) + entry
    if alpn:
        lst = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        exts += struct.pack("!HHH", 0x0010, len(lst) + 2, len(lst)) + lst
    if ech:
        exts += struct.pack("!HH", 0xFE0D, 4) + b"\x00\x00\x01\x00"
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def build_dns_response(name: str, ips: list[str], txid: int = 0x1234) -> bytes:
    """A DNS response answering ``name`` with A/AAAA records (names compressed)."""
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    msg = struct.pack("!HHHHHH", txid, 0x8180, 1, len(ips), 0, 0) + qname
    msg += struct.pack("!HH", 1, 1)
    for ip in ips:
        v6 = ":" in ip
        rdata = socket.inet_pton(socket.AF_INET6 if v6 else socket.AF_INET, ip)
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 28 if v6 else 1, 1, 300, len(rdata)) + rdata
    return msg
