from helpers import ethernet, ipv4_tcp, ipv6_udp

from netmon.packets import LINKTYPE_ETHERNET, TCP, UDP, parse_frame, parse_ip


def test_ipv4_tcp_syn():
    p = parse_ip(ipv4_tcp("192.168.1.10", "1.2.3.4", 50000, 443, flags=0x02, payload=b"x" * 100))
    assert (p.src, p.dst, p.proto, p.sport, p.dport) == ("192.168.1.10", "1.2.3.4", TCP, 50000, 443)
    assert p.length == 140
    assert p.syn and not p.ack


def test_ipv6_udp():
    p = parse_ip(ipv6_udp("fe80::1", "2001:db8::2", 5353, 53, b"abc"))
    assert (p.src, p.dst, p.proto, p.sport, p.dport) == ("fe80::1", "2001:db8::2", UDP, 5353, 53)
    assert p.length == 40 + 8 + 3


def test_ethernet_with_vlan():
    frame = ethernet(ipv4_tcp("10.0.0.1", "10.0.0.2", 1234, 22), vlan=True)
    p = parse_frame(frame, LINKTYPE_ETHERNET)
    assert p.dport == 22


def test_non_ip_is_ignored():
    assert parse_frame(ethernet(b"\x00\x01" + b"\x00" * 26, ethertype=0x0806), LINKTYPE_ETHERNET) is None
    assert parse_ip(b"") is None
    assert parse_ip(b"\x45" + b"\x00" * 5) is None


def test_tcp_seq_flags_and_payload():
    from netmon.packets import TCP_ACK, TCP_PSH, flags_text

    raw = ipv4_tcp("10.0.0.1", "10.0.0.2", 40000, 80, flags=TCP_PSH | TCP_ACK, payload=b"GET / HTTP/1.1\r\n" * 8)
    p = parse_ip(raw)
    assert p.payload_len == 128 and p.payload == b""  # payload only when asked for
    assert p.seq == 0 and p.ack_no == 0 and flags_text(p.tcp_flags) == "P."
    p = parse_ip(raw, payload=64)
    assert p.payload == (b"GET / HTTP/1.1\r\n" * 4)
    assert parse_ip(ipv6_udp("::1", "::1", 1, 53, b"xyz"), payload=64).payload == b"xyz"
