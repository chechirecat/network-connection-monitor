from netmon.classify import INTERNET, INTRANET, Classifier, dst_is_server
from netmon.model import TrafficModel
from netmon.packets import TCP, UDP, Packet
from netmon.views import GROUP_HOST, GROUP_SERVICE, build_groups, sort_groups


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def test_scope():
    c = Classifier(["198.18.0.0/15"])
    assert c.scope("192.168.1.2", "10.1.1.1") == INTRANET
    assert c.scope("192.168.1.2", "8.8.8.8") == INTERNET
    assert c.scope("fe80::1", "ff02::fb") == INTRANET
    assert c.scope("192.168.1.2", "198.18.5.5") == INTRANET
    assert c.scope("203.0.113.5", "192.168.1.2") == INTERNET


def test_port_heuristic():
    assert dst_is_server(51234, 443)
    assert not dst_is_server(443, 51234)
    assert dst_is_server(68, 67)
    assert dst_is_server(40000, 9000)


def test_syn_decides_client_and_direction():
    clock = Clock()
    m = TrafficModel(clock=clock)
    # a client using a "server-ish" source port still gets recognised via SYN
    m.add(Packet("192.168.1.5", "192.168.1.9", TCP, 8080, 40000, 60, syn=True))
    m.add(Packet("192.168.1.9", "192.168.1.5", TCP, 40000, 8080, 1000, syn=True, ack=True))
    clock.t = 1.0
    (pv,) = m.tick()
    assert (pv.client, pv.server, pv.port) == ("192.168.1.5", "192.168.1.9", 40000)
    assert (pv.up, pv.down) == (60, 1000)


def test_rates_and_expiry():
    clock = Clock()
    m = TrafficModel(clock=clock, expire=10, tau=0.001)
    m.add(Packet("192.168.1.5", "8.8.8.8", UDP, 50000, 53, 500))
    clock.t = 1.0
    (pv,) = m.tick()
    assert round(pv.rate_up) == 500 and pv.scope == INTERNET
    clock.t = 2.0
    (pv,) = m.tick()
    assert pv.rate == 0 and pv.total == 500
    clock.t = 20.0
    assert m.tick() == []


def test_grouping():
    clock = Clock()
    m = TrafficModel(clock=clock)
    for client, port, n in [("192.168.1.2", 443, 100), ("192.168.1.3", 443, 300), ("192.168.1.2", 80, 50)]:
        m.add(Packet(client, "1.2.3.4", TCP, 50000, port, n, syn=True))
    m.add(Packet("192.168.1.2", "192.168.1.1", UDP, 50001, 53, 10))
    clock.t = 1.0
    pairs = m.tick()

    by_host = build_groups(pairs, GROUP_HOST)
    assert len(by_host) == 2
    g = next(g for g in by_host if g.server == "1.2.3.4")
    assert {c.ip: c.total for c in g.clients} == {"192.168.1.2": 150, "192.168.1.3": 300}
    assert g.ports == {(443, TCP), (80, TCP)}

    by_service = build_groups(pairs, GROUP_SERVICE)
    assert len(by_service) == 3

    ordered = sort_groups(by_host, "size", "total")
    assert ordered[0].server == "1.2.3.4"
    assert [c.ip for c in ordered[0].clients] == ["192.168.1.3", "192.168.1.2"]
    assert sort_groups(by_host, "size", "total", reverse=True)[0].server == "192.168.1.1"
