from helpers import ipv4_tcp

from netmon.hostnames import (
    SOURCE_DNS, SOURCE_ECH, SOURCE_SNI, HostNames, build_client_hello, build_dns_response,
    parse_client_hello, parse_dns_answers,
)
from netmon.packets import TCP, TCP_ACK, TCP_PSH, UDP, Packet, parse_ip


def test_parse_client_hello():
    h = parse_client_hello(build_client_hello("api.example.com", alpn=("h2",)))
    assert (h.sni, h.alpn, h.ech) == ("api.example.com", ["h2"], False)
    assert parse_client_hello(build_client_hello("cloudflare-ech.com", ech=True)).ech
    assert parse_client_hello(build_client_hello(None)).sni is None
    assert parse_client_hello(b"\x17\x03\x03\x00\x10" + bytes(16)) is None  # application data
    assert parse_client_hello(build_client_hello("x.com")[:40]) is None  # truncated


def test_parse_dns_answers():
    msg = build_dns_response("discord.com", ["162.159.135.232", "2606:4700::6810:1"])
    assert parse_dns_answers(msg) == [("162.159.135.232", "discord.com"), ("2606:4700::6810:1", "discord.com")]
    assert parse_dns_answers(msg[:2] + b"\x01\x00" + msg[4:]) == []  # a query, not a response
    assert parse_dns_answers(msg[:20]) == []  # truncated


def seg(payload, seq, src="192.168.1.2", dst="104.18.29.17"):
    return Packet(src, dst, TCP, 50000, 443, 40 + len(payload), ack=True, tcp_flags=TCP_PSH | TCP_ACK,
                  seq=seq, payload_len=len(payload), payload=payload)


def test_sni_from_single_and_split_hello():
    names = HostNames()
    names.observe(seg(build_client_hello("www.example.org"), 1))
    assert names.best("104.18.29.17") == "www.example.org"
    assert names.connection("192.168.1.2", 50000, "104.18.29.17", 443).sni == "www.example.org"

    # ClientHello larger than one segment, SNI in the second part (Chrome-style)
    hello = build_client_hello("chat.example.net", padding=1500)
    names = HostNames()
    names.observe(seg(hello[:1400], 1000))
    assert names.best("104.18.29.17") is None and names.wants_payload("192.168.1.2", 50000, "104.18.29.17", 443)
    names.observe(seg(hello[1400:], 2400))
    assert names.best("104.18.29.17") == "chat.example.net"
    assert not names.pending

    # wrong sequence number: the partial hello is dropped, not mis-assembled
    names = HostNames()
    names.observe(seg(hello[:1400], 1000))
    names.observe(seg(hello[1400:], 9999))
    assert names.best("104.18.29.17") is None


def test_ranking_and_shared_addresses():
    names = HostNames()
    names.add("104.18.29.17", "cloudflare-ech.com", SOURCE_ECH)
    assert names.best("104.18.29.17") == "cloudflare-ech.com"
    names.add("104.18.29.17", "chatgpt.com", SOURCE_DNS)
    assert names.best("104.18.29.17") == "chatgpt.com"  # DNS beats the ECH decoy
    names.add("104.18.29.17", "openai.com", SOURCE_SNI)
    assert names.best("104.18.29.17") == "openai.com +1"
    assert [i.source for i in names.names("104.18.29.17")] == [SOURCE_SNI, SOURCE_DNS, SOURCE_ECH]


def test_parser_keeps_hello_payload_only_when_sniffing():
    hello = build_client_hello("www.example.org")
    raw = ipv4_tcp("192.168.1.2", "1.2.3.4", 50000, 443, flags=TCP_PSH | TCP_ACK, payload=hello)
    assert parse_ip(raw).payload == b""
    assert parse_ip(raw, sniff=lambda *a: False).payload == hello
    other = ipv4_tcp("192.168.1.2", "1.2.3.4", 50000, 443, flags=TCP_ACK, payload=b"\x17\x03\x03" + bytes(100))
    assert parse_ip(other, sniff=lambda *a: False).payload == b""
    assert parse_ip(other, sniff=lambda *a: True).payload  # continuation of a pending hello


def test_dns_observed_from_udp():
    names = HostNames()
    dns = build_dns_response("archive.ubuntu.com", ["91.189.91.38"])
    names.observe(Packet("192.168.1.1", "192.168.1.2", UDP, 53, 40000, 28 + len(dns),
                         payload_len=len(dns), payload=dns))
    assert names.best("91.189.91.38") == "archive.ubuntu.com"
