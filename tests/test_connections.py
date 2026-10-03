from netmon.detail import bar_chart, dump_text
from netmon.focus import Focus
from netmon.model import (
    STATE_ACTIVE, STATE_CLOSED, STATE_CLOSING, STATE_OPEN, STATE_RESET, STATE_SYN, TrafficModel,
)
from netmon.packets import TCP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, UDP, Packet


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def tcp(src, dst, sport, dport, flags, length=60, payload=b""):
    return Packet(src, dst, TCP, sport, dport, length, syn=bool(flags & TCP_SYN), ack=bool(flags & TCP_ACK),
                  tcp_flags=flags, seq=1, ack_no=1, payload_len=len(payload), payload=payload)


C, S = "192.168.1.2", "1.2.3.4"


def test_connection_states_and_counters():
    clock = Clock()
    m = TrafficModel(clock=clock)
    m.add(tcp(C, S, 50000, 443, TCP_SYN))
    states = lambda: {c.client_port: c.state for c in m.connections(lambda p: True)}
    assert states() == {50000: STATE_SYN}
    m.add(tcp(S, C, 443, 50000, TCP_SYN | TCP_ACK))
    m.add(tcp(C, S, 50000, 443, TCP_ACK, length=1000))
    assert states() == {50000: STATE_OPEN}
    m.add(tcp(C, S, 50000, 443, TCP_FIN | TCP_ACK))
    assert states() == {50000: STATE_CLOSING}
    m.add(tcp(S, C, 443, 50000, TCP_FIN | TCP_ACK))
    assert states() == {50000: STATE_CLOSED}

    m.add(tcp(C, S, 50001, 443, TCP_ACK))  # mid-stream
    m.add(tcp(C, S, 50002, 443, TCP_RST))
    m.add(Packet(C, "8.8.8.8", UDP, 5353, 53, 80))
    assert states() == {50000: STATE_CLOSED, 50001: STATE_ACTIVE, 50002: STATE_RESET, 5353: STATE_ACTIVE}

    (c,) = [c for c in m.connections(Focus(server=S).matches) if c.client_port == 50000]
    assert (c.up, c.down, c.packets, c.server_port, c.scope) == (1120, 120, 5, 443, "internet")
    assert len(m.connections(Focus(server="8.8.8.8").matches)) == 1


def test_history_sums_matching_pairs():
    clock = Clock()
    m = TrafficModel(clock=clock)
    for t in (1.0, 2.0, 3.0):
        m.add(Packet(C, S, UDP, 50000, 53, 100))
        m.add(Packet("192.168.1.3", S, UDP, 50000, 53, 50))
        clock.t = t
        m.tick()
    assert m.history(Focus(server=S).matches) == [(150.0, 0.0)] * 3
    assert m.history(Focus(client=C).matches) == [(100.0, 0.0)] * 3


def test_dump_records_only_watched_pairs():
    m = TrafficModel()
    m.add(tcp(C, S, 50000, 443, TCP_ACK))
    assert not m.dump  # nothing watched
    m.set_watch(Focus(client=C).matches)
    m.add(tcp(C, S, 50000, 443, TCP_ACK, payload=b"hello"))
    m.add(tcp(S, C, 443, 50000, TCP_ACK))
    m.add(tcp("192.168.1.9", S, 50000, 443, TCP_ACK))
    entries = m.dump_since(0)
    assert [e.up for e in entries] == [True, False]
    assert m.dump_since(entries[0].seq) == entries[1:]
    text = dump_text(entries[0], show_payload=True).plain
    assert "192.168.1.2:50000 → 1.2.3.4:443" in text and "[.]" in text and "hello" in text
    assert "hello" not in dump_text(entries[0], show_payload=False).plain
    m.set_watch(None)
    assert not m.dump


def test_bar_chart():
    rows = bar_chart([0, 4, 8], width=3, height=1)
    assert rows == [" ▄█"]
    assert bar_chart([0, 0], width=4, height=2) == ["    ", "    "]
