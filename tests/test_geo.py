from netmon.geo import EASTERN, EUROPE, GERMANY, LOCAL, REST, UNKNOWN, WESTERN, GeoDB, region_of
from netmon.model import TrafficModel
from netmon.packets import TCP, Packet
from netmon.views import build_groups

ROWS = [
    ("46.4.0.0", "46.4.255.255", "DE"),
    ("77.88.0.0", "77.88.63.255", "RU"),
    ("8.8.8.0", "8.8.8.255", "US"),
    ("2a00:1450::", "2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff", "IE"),
    ("203.0.113.0", "203.0.113.255", "ZZ"),
]


def test_lookup():
    db = GeoDB.from_rows(ROWS)
    assert db.lookup("46.4.12.1") == "DE"
    assert db.lookup("8.8.8.8") == "US"
    assert db.lookup("8.8.9.1") is None
    assert db.lookup("2a00:1450:4001::1") == "IE"
    assert db.lookup("203.0.113.5") is None  # ZZ = unassigned
    assert db.lookup("not an ip") is None


def test_regions():
    assert [region_of(c) for c in ("DE", "FR", "US", "RU", "BR", None)] == [
        GERMANY, EUROPE, WESTERN, EASTERN, REST, UNKNOWN,
    ]


def test_remote_country_on_boxes():
    db = GeoDB.from_rows(ROWS)
    m = TrafficModel(geo=db.lookup)
    m.add(Packet("192.168.1.2", "46.4.0.1", TCP, 50000, 443, 100, syn=True))  # outbound
    m.add(Packet("77.88.1.1", "192.168.1.9", TCP, 50000, 22, 100, syn=True))  # inbound
    m.add(Packet("192.168.1.2", "192.168.1.9", TCP, 50001, 22, 100, syn=True))  # local
    groups = build_groups(m.tick())

    out = next(g for g in groups if g.server == "46.4.0.1")
    assert (out.cc, out.region, out.clients[0].region) == ("DE", GERMANY, GERMANY)

    inbound = next(g for g in groups if g.scope == "internet" and g.server == "192.168.1.9")
    assert inbound.region == LOCAL
    assert (inbound.clients[0].cc, inbound.clients[0].region) == ("RU", EASTERN)

    local = next(g for g in groups if g.scope == "intranet")
    assert local.region == LOCAL and local.clients[0].region == LOCAL
