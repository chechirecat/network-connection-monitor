import socket
import struct


def ipv4_tcp(src, dst, sport, dport, flags=0x10, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return ip + tcp


def ipv6_udp(src, dst, sport, dport, payload=b""):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!IHBB", 6 << 28, len(udp), 17, 64)
    ip += socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return ip + udp


def ethernet(ip_packet, ethertype=0x0800, vlan=False):
    hdr = b"\x02" * 6 + b"\x04" * 6
    if vlan:
        hdr += struct.pack("!HH", 0x8100, 7)
    return hdr + struct.pack("!H", ethertype) + ip_packet


def pcap(frames, linktype=1):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1000 + i, 0, len(f), len(f)) + f
    return out
