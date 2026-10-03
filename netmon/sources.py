"""Packet sources. Each runs in a daemon thread and feeds Packets to a sink."""

from __future__ import annotations

import os
import random
import socket
import struct
import sys
import threading
import time
from typing import BinaryIO, Callable

from .hostnames import build_client_hello, build_dns_response
from .packets import TCP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN, UDP, Packet, parse_frame, parse_ip

Sink = Callable[[Packet], None]

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


class SourceError(RuntimeError):
    pass


class Source:
    description = "?"

    def __init__(self) -> None:
        self.payload_bytes = 0  # >0: keep that many payload bytes per packet (dump view, opt-in)
        self.sniff = None  # packets.Sniff: keep TLS ClientHellos / DNS answers for hostname learning
        self.finished = False
        self.error: str | None = None
        self._stop = threading.Event()

    def start(self, sink: Sink) -> None:
        threading.Thread(target=self._guarded, args=(sink,), daemon=True, name=type(self).__name__).start()

    def stop(self) -> None:
        self._stop.set()

    def _guarded(self, sink: Sink) -> None:
        try:
            self.run(sink)
        except Exception as e:  # surfaced in the status bar
            self.error = f"{type(e).__name__}: {e}"
        finally:
            self.finished = True

    def run(self, sink: Sink) -> None:
        raise NotImplementedError


class LiveSource(Source):
    """Linux AF_PACKET capture. SOCK_DGRAM strips the link layer, so any
    interface type (ethernet, wifi, tun/wireguard, loopback) works."""

    def __init__(self, iface: str | None = None) -> None:
        super().__init__()
        self.iface = iface
        self.description = f"live {iface or 'all interfaces'}"
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
        except PermissionError:
            raise SourceError(
                "capturing needs root: run `sudo .venv/bin/netmon`, or keep the UI unprivileged with "
                "`sudo tcpdump -i any -U -w - | .venv/bin/netmon --pcap -`"
            ) from None
        except AttributeError:
            raise SourceError("live capture is only supported on Linux; use --pcap or --demo") from None
        if iface:
            try:
                self.sock.bind((iface, 0))
            except OSError as e:
                raise SourceError(f"cannot capture on {iface!r}: {e.strerror}") from None
        self.sock.settimeout(0.5)

    def run(self, sink: Sink) -> None:
        buf = bytearray(65536)
        view = memoryview(buf)
        while not self._stop.is_set():
            try:
                n, addr = self.sock.recvfrom_into(buf)
            except TimeoutError:
                continue
            # Loopback traffic shows up twice (outgoing + incoming); keep one copy.
            if addr[2] == PACKET_OUTGOING and addr[0] == "lo":
                continue
            pkt = parse_ip(view[:n], self.payload_bytes, self.sniff)
            if pkt is not None:
                sink(pkt)
        self.sock.close()


class PcapSource(Source):
    """Classic pcap reader (``tcpdump -w``). ``-`` reads stdin, which allows
    ``sudo tcpdump -i eth0 -w - | netmon --pcap -`` without running the UI as root.
    Files are replayed at their recorded pace unless ``realtime`` is False."""

    def __init__(self, path: str, realtime: bool = True) -> None:
        super().__init__()
        self.path = path
        self.realtime = realtime and path != "-"
        self.description = "pcap stdin" if path == "-" else f"pcap {path}"
        # stdin gets its own descriptor so fd 0 can be handed back to the terminal
        self.fh: BinaryIO = os.fdopen(os.dup(sys.stdin.fileno()), "rb") if path == "-" else open(path, "rb")
        header = self._read(24)
        if header is None:
            raise SourceError("empty pcap input")
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            self.endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self.endian = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise SourceError("pcapng is not supported; convert with `editcap -F pcap in.pcapng out.pcap`")
        else:
            raise SourceError("not a pcap file")
        self.ts_div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        (self.linktype,) = struct.unpack(self.endian + "I", header[20:24])
        self.linktype &= 0x0FFFFFFF

    def _read(self, n: int) -> bytes | None:
        data = self.fh.read(n)
        return data if data and len(data) == n else None

    def run(self, sink: Sink) -> None:
        rec_fmt = self.endian + "IIII"
        first_ts = start = None
        while not self._stop.is_set():
            rec = self._read(16)
            if rec is None:
                break
            sec, frac, incl, _orig = struct.unpack(rec_fmt, rec)
            frame = self._read(incl)
            if frame is None:
                break
            if self.realtime:
                ts = sec + frac / self.ts_div
                if first_ts is None:
                    first_ts, start = ts, time.monotonic()
                delay = (ts - first_ts) - (time.monotonic() - start)
                if delay > 0 and self._stop.wait(delay):
                    break
            pkt = parse_frame(frame, self.linktype, self.payload_bytes, self.sniff)
            if pkt is not None:
                sink(pkt)


class DemoSource(Source):
    """Synthetic traffic for trying the UI without root."""

    description = "demo"

    LAN = [f"192.168.1.{i}" for i in (10, 11, 12, 15, 23, 42, 77)]
    INTERNET_SERVERS = [
        ("142.250.185.78", 443, TCP, 400_000),
        ("140.82.121.4", 443, TCP, 60_000),
        ("151.101.1.140", 443, TCP, 120_000),
        ("104.16.132.229", 443, TCP, 80_000),
        ("8.8.8.8", 53, UDP, 2_000),
        ("1.1.1.1", 853, TCP, 3_000),
        ("185.199.108.153", 80, TCP, 20_000),
        ("91.189.91.38", 80, TCP, 900_000),
        ("162.159.135.234", 443, UDP, 250_000),
        ("52.84.150.11", 443, TCP, 30_000),
        ("46.4.0.10", 443, TCP, 180_000),
        ("85.13.150.20", 993, TCP, 8_000),
        ("77.88.55.88", 443, TCP, 25_000),
        ("220.181.38.148", 443, TCP, 15_000),
        ("200.147.67.142", 443, TCP, 12_000),
        ("31.13.84.36", 443, TCP, 90_000),
    ]
    LAN_SERVERS = [
        ("192.168.1.1", 53, UDP, 3_000),
        ("192.168.1.5", 445, TCP, 1_500_000),
        ("192.168.1.20", 22, TCP, 15_000),
        ("10.0.0.12", 8080, TCP, 200_000),
        ("192.168.1.30", 631, TCP, 5_000),
        ("224.0.0.251", 5353, UDP, 800),
        ("192.168.1.42", 32400, TCP, 2_500_000),
    ]
    # a host on the internet using a server in the LAN (port forward)
    INBOUND = [("203.0.113.50", "192.168.1.42", 32400, TCP, 300_000)]
    # Names announced in TLS ClientHellos (SNI) / DNS answers; 162.159.135.234 is QUIC (UDP),
    # whose hello is encrypted, so it is only named through the DNS answer.
    SNI = {
        "142.250.185.78": "www.google.com", "140.82.121.4": "github.com", "151.101.1.140": "www.reddit.com",
        "104.16.132.229": "discord.com", "1.1.1.1": "one.one.one.one", "52.84.150.11": "d3f8ab2c1.cloudfront.net",
        "46.4.0.10": "cloud.example.de", "77.88.55.88": "yandex.ru", "220.181.38.148": "www.baidu.com",
        "200.147.67.142": "www.uol.com.br", "31.13.84.36": "www.facebook.com",
    }
    DNS = {"162.159.135.234": "discord.media", "91.189.91.38": "archive.ubuntu.com",
           "185.199.108.153": "objects.githubusercontent.com"}
    # Fallback countries when no GeoIP database is installed (also used by tests).
    GEO_ROWS = [
        (ip, ip, cc)
        for ip, cc in [
            ("142.250.185.78", "US"), ("140.82.121.4", "GB"), ("151.101.1.140", "US"),
            ("104.16.132.229", "US"), ("8.8.8.8", "US"), ("1.1.1.1", "AU"), ("185.199.108.153", "US"),
            ("91.189.91.38", "GB"), ("162.159.135.234", "NL"), ("52.84.150.11", "JP"),
            ("46.4.0.10", "DE"), ("85.13.150.20", "DE"), ("77.88.55.88", "RU"),
            ("220.181.38.148", "CN"), ("200.147.67.142", "BR"), ("31.13.84.36", "IE"),
            ("203.0.113.50", "FR"),
        ]
    ]

    def run(self, sink: Sink) -> None:
        rng = random.Random(1)
        flows = []  # [client, cport, server, sport, proto, base_rate, level, ttl]
        for server, port, proto, rate in self.INTERNET_SERVERS + self.LAN_SERVERS:
            for client in rng.sample(self.LAN, rng.randint(1, 4)):
                if client != server:
                    flows.append([client, rng.randint(32768, 60999), server, port, proto, rate, 1.0, None])
        for client, server, port, proto, rate in self.INBOUND:
            flows.append([client, rng.randint(32768, 60999), server, port, proto, rate, 1.0, None])
        for f in flows:
            self._open(sink, f)
        # the LAN's DNS lookups for the servers that are only named via DNS
        for ip, name in self.DNS.items():
            dns = build_dns_response(name, [ip])
            sink(Packet("192.168.1.1", self.LAN[0], UDP, 53, 40000, 28 + len(dns), payload_len=len(dns), payload=dns))
        dt = 0.1
        while not self._stop.wait(dt):
            if rng.random() < 0.05:  # short-lived extra connection
                server, port, proto, rate = rng.choice(self.INTERNET_SERVERS + self.LAN_SERVERS)
                client = rng.choice(self.LAN)
                if client != server:
                    f = [client, rng.randint(32768, 60999), server, port, proto, rate * 2, 1.0, rng.randint(20, 150)]
                    flows.append(f)
                    self._open(sink, f)
            for f in list(flows):
                f[6] = min(max(f[6] * rng.uniform(0.85, 1.18), 0.02), 6.0)
                if f[7] is not None:
                    f[7] -= 1
                    if f[7] <= 0:
                        flows.remove(f)
                        self._close(sink, f)
                        continue
                total = f[5] * f[6] * dt
                down = total * rng.uniform(0.6, 0.95)
                client, cport, server, sport, proto = f[:5]
                sink(self._packet(rng, client, server, proto, cport, sport, int(total - down) + 40, True))
                sink(self._packet(rng, server, client, proto, sport, cport, int(down) + 40, False))

    def _packet(self, rng, src, dst, proto, sport, dport, length, up) -> Packet:
        """A synthetic packet; payload looks like the protocol (plain HTTP/DNS, TLS records otherwise)."""
        payload_len = max(length - 40, 0)
        payload = b""
        if self.payload_bytes:
            port = dport if up else sport
            if port == 80:
                payload = (b"GET /ubuntu/dists/noble/InRelease HTTP/1.1\r\nHost: archive.ubuntu.com\r\n"
                           if up else b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n")
            elif port == 53:
                payload = bytes([rng.randrange(256), rng.randrange(256)]) + b"\x01\x00\x00\x01" + b"\x07example\x03com\x00"
            else:
                payload = b"\x17\x03\x03" + rng.randbytes(61)  # looks like TLS application data
            payload = payload[: min(self.payload_bytes, payload_len)]
        flags = TCP_ACK | TCP_PSH if proto == TCP else 0
        return Packet(src, dst, proto, sport, dport, length, ack=proto == TCP, tcp_flags=flags,
                      seq=rng.getrandbits(32) if proto == TCP else None, payload_len=payload_len, payload=payload)

    @staticmethod
    def _close(sink: Sink, f) -> None:
        client, cport, server, sport, proto = f[:5]
        if proto == TCP:
            for src, dst, sp, dp in ((client, server, cport, sport), (server, client, sport, cport)):
                sink(Packet(src, dst, proto, sp, dp, 52, ack=True, tcp_flags=TCP_FIN | TCP_ACK))

    def _open(self, sink: Sink, f) -> None:
        client, cport, server, sport, proto = f[:5]
        if proto == TCP:
            sink(Packet(client, server, proto, cport, sport, 60, syn=True, tcp_flags=TCP_SYN))
            sink(Packet(server, client, proto, sport, cport, 60, syn=True, ack=True, tcp_flags=TCP_SYN | TCP_ACK))
            if server in self.SNI and sport in (443, 853, 993):
                hello = build_client_hello(self.SNI[server])
                sink(Packet(client, server, proto, cport, sport, 52 + len(hello), ack=True,
                            tcp_flags=TCP_PSH | TCP_ACK, seq=1, payload_len=len(hello), payload=hello))
        else:
            sink(Packet(client, server, proto, cport, sport, 60))
