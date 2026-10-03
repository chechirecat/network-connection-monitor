from netmon.packets import TCP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN, UDP, Packet
from netmon.stream import KIND_DATA, KIND_EVENT, KIND_GAP, KIND_RETRANS, MAX_BYTES, StreamFollower

C, S = ("192.168.1.2", 50000), ("1.2.3.4", 80)


class Clock:
    t = 100.0

    def __call__(self):
        return self.t


def seg(data, seq, up=True, flags=TCP_PSH | TCP_ACK):
    (src, sp), (dst, dp) = (C, S) if up else (S, C)
    return Packet(src, dst, TCP, sp, dp, 40 + len(data), syn=bool(flags & TCP_SYN), ack=bool(flags & TCP_ACK),
                  tcp_flags=flags, seq=seq, payload_len=len(data), payload=data)


def follower():
    clock = Clock()
    f = StreamFollower(clock=clock)
    f.follow(C[0], C[1], S[0], S[1], TCP)
    return f, clock


def text(f, up=True):
    return b"".join(c.data for c in f.chunks if c.kind == KIND_DATA and c.up == up)


def test_in_order_with_handshake_and_both_directions():
    f, _ = follower()
    f.observe(seg(b"", 999, flags=TCP_SYN))
    f.observe(seg(b"", 4999, up=False, flags=TCP_SYN | TCP_ACK))
    f.observe(seg(b"GET / HTTP/1.1\r\n", 1000))
    f.observe(seg(b"Host: x\r\n\r\n", 1016))
    f.observe(seg(b"HTTP/1.1 200 OK\r\n", 5000, up=False))
    f.observe(seg(b"", 1027, flags=TCP_FIN | TCP_ACK))
    assert text(f) == b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    assert text(f, up=False) == b"HTTP/1.1 200 OK\r\n"
    assert not f.mid_stream and f.dirs[True].syn_seen
    assert [c.data for c in f.chunks if c.kind == KIND_EVENT] == [b"SYN", b"SYN+ACK", b"FIN"]


def test_out_of_order_is_reordered():
    f, _ = follower()
    f.observe(seg(b"aaaa", 0))
    f.observe(seg(b"cccc", 8))  # early
    assert text(f) == b"aaaa"
    f.observe(seg(b"bbbb", 4))  # fills the hole
    assert text(f) == b"aaaabbbbcccc"
    assert f.dirs[True].out_of_order == 1 and f.dirs[True].gaps == 0


def test_retransmission_and_overlap():
    f, _ = follower()
    f.observe(seg(b"aaaa", 0))
    f.observe(seg(b"aaaa", 0))  # full duplicate
    f.observe(seg(b"aabb", 2))  # overlaps 2 old bytes, 2 new
    assert text(f) == b"aaaabb"
    assert f.dirs[True].retrans == 6
    assert [c.size for c in f.chunks if c.kind == KIND_RETRANS] == [4]


def test_gap_after_timeout():
    f, clock = follower()
    f.observe(seg(b"aaaa", 0))
    f.observe(seg(b"cccc", 8))
    clock.t += 0.5
    f.flush()
    assert text(f) == b"aaaa"  # still waiting
    clock.t += 1.0
    f.flush()
    assert text(f) == b"aaaacccc"
    (gap,) = [c for c in f.chunks if c.kind == KIND_GAP]
    assert (gap.offset, gap.size) == (4, 4) and f.dirs[True].gaps == 4
    assert [k for _, _, k in f.dirs[True].ranges] == ["data", "gap", "data"]


def test_mid_stream_start_and_sequence_wraparound():
    f, _ = follower()
    f.observe(seg(b"xy", 2**32 - 1))  # first seen without SYN, right before wraparound
    f.observe(seg(b"z", 1))
    assert f.mid_stream and text(f) == b"xyz"


def test_only_target_and_cap():
    f, _ = follower()
    other = Packet("192.168.1.9", "1.2.3.4", TCP, 50000, 80, 44, seq=0, payload_len=4, payload=b"nope")
    f.observe(other)
    assert not f.chunks
    assert f.wants_payload(*S, *C) and not f.wants_payload("192.168.1.9", 50000, *S)
    big = b"x" * 60000
    for i in range(MAX_BYTES // len(big) + 2):
        f.observe(seg(big, i * len(big)))
    assert len(text(f)) == MAX_BYTES and f.dirs[True].truncated
    assert f.dirs[True].received > MAX_BYTES
    f.stop()
    assert f.target is None and not f.chunks and not f.wants_payload(*C, *S)


def test_udp_datagrams():
    f = StreamFollower()
    f.follow("192.168.1.2", 5353, "8.8.8.8", 53, UDP)
    f.observe(Packet("192.168.1.2", "8.8.8.8", UDP, 5353, 53, 40, payload_len=3, payload=b"q01"))
    f.observe(Packet("8.8.8.8", "192.168.1.2", UDP, 53, 5353, 40, payload_len=3, payload=b"a01"))
    assert [(c.up, c.data) for c in f.chunks] == [(True, b"q01"), (False, b"a01")]
