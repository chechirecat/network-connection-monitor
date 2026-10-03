"""Minimal packet parsing: link layer -> IPv4/IPv6 -> TCP/UDP ports."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

TCP = 6
UDP = 17
ICMP = 1
ICMP6 = 58

PROTO_NAMES = {TCP: "tcp", UDP: "udp", ICMP: "icmp", ICMP6: "icmp6"}

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TYPES = (0x8100, 0x88A8, 0x9100)

# pcap link types we understand
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

_IPV6_EXT_HEADERS = (0, 43, 60)  # hop-by-hop, routing, destination options
_IPV6_FRAGMENT = 44


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto))


@dataclass(slots=True, frozen=True)
class Packet:
    src: str
    dst: str
    proto: int
    sport: int | None
    dport: int | None
    length: int
    syn: bool = False
    ack: bool = False


def parse_ip(data: bytes | memoryview) -> Packet | None:
    """Parse a packet starting at the IP header (version is taken from the first nibble)."""
    if len(data) < 1:
        return None
    version = data[0] >> 4
    if version == 4:
        return _parse_ipv4(data)
    if version == 6:
        return _parse_ipv6(data)
    return None


def _parse_ipv4(data: bytes | memoryview) -> Packet | None:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20:
        return None
    total_len, frag = struct.unpack_from("!H2xH", data, 2)
    proto = data[9]
    src = socket.inet_ntop(socket.AF_INET, bytes(data[12:16]))
    dst = socket.inet_ntop(socket.AF_INET, bytes(data[16:20]))
    length = total_len or len(data)  # total_len is 0 for some offloaded (TSO) packets
    first_fragment = (frag & 0x1FFF) == 0
    return _parse_l4(data, ihl if first_fragment else None, proto, src, dst, length)


def _parse_ipv6(data: bytes | memoryview) -> Packet | None:
    if len(data) < 40:
        return None
    (payload_len,) = struct.unpack_from("!H", data, 4)
    nxt = data[6]
    src = socket.inet_ntop(socket.AF_INET6, bytes(data[8:24]))
    dst = socket.inet_ntop(socket.AF_INET6, bytes(data[24:40]))
    length = 40 + payload_len if payload_len else len(data)
    off: int | None = 40
    while off is not None and nxt in (*_IPV6_EXT_HEADERS, _IPV6_FRAGMENT):
        if len(data) < off + 8:
            off = None
            break
        if nxt == _IPV6_FRAGMENT:
            (frag,) = struct.unpack_from("!H", data, off + 2)
            nxt = data[off]
            off = off + 8 if (frag >> 3) == 0 else None
        else:
            nxt, ext_len = data[off], (data[off + 1] + 1) * 8
            off += ext_len
    return _parse_l4(data, off, nxt, src, dst, length)


def _parse_l4(data, off: int | None, proto: int, src: str, dst: str, length: int) -> Packet:
    sport = dport = None
    syn = ack = False
    if off is not None and proto in (TCP, UDP) and len(data) >= off + 4:
        sport, dport = struct.unpack_from("!HH", data, off)
        if proto == TCP and len(data) >= off + 14:
            flags = data[off + 13]
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
    return Packet(src, dst, proto, sport, dport, length, syn, ack)


def parse_ethernet(frame: bytes | memoryview) -> Packet | None:
    if len(frame) < 14:
        return None
    off = 12
    (ethertype,) = struct.unpack_from("!H", frame, off)
    while ethertype in VLAN_TYPES and len(frame) >= off + 6:
        off += 4
        (ethertype,) = struct.unpack_from("!H", frame, off)
    if ethertype not in (ETH_P_IP, ETH_P_IPV6):
        return None
    return parse_ip(frame[off + 2 :])


def parse_frame(frame: bytes | memoryview, linktype: int) -> Packet | None:
    """Parse a captured frame of the given pcap link type."""
    if linktype == LINKTYPE_ETHERNET:
        return parse_ethernet(frame)
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return parse_ip(frame)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        (ethertype,) = struct.unpack_from("!H", frame, 14)
        return parse_ip(frame[16:]) if ethertype in (ETH_P_IP, ETH_P_IPV6) else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        (ethertype,) = struct.unpack_from("!H", frame, 0)
        return parse_ip(frame[20:]) if ethertype in (ETH_P_IP, ETH_P_IPV6) else None
    if linktype == LINKTYPE_NULL:
        return parse_ip(frame[4:])
    return None
