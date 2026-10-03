import pytest

from netmon.filters import FilterError, parse_filter, parse_size
from netmon.model import PairView
from netmon.packets import TCP, UDP


def pair(client="192.168.1.2", server="1.2.3.4", port=443, proto=TCP, scope="internet", rate=0.0, cc="DE"):
    return PairView(client, server, port, proto, scope, 1, frozenset({50000}), 0, 0, 1, rate, 0.0, 0.0,
                    remote=server if scope == "internet" else None, remote_cc=cc)


NAMES = {"1.2.3.4": "edge.example.com"}.get


def match(expr, p):
    return parse_filter(expr)(p, NAMES)


def test_terms():
    p = pair(rate=20_000)
    assert match("port 443", p)
    assert match("port 50000", p)
    assert not match("port 22", p)
    assert match("server example", p)
    assert not match("client example", p)
    assert match("net 192.168.0.0/16", p)
    assert match("tcp internet min 10k", p)
    assert not match("min 1M", p)
    assert match("https", p)
    assert not match("!internet", p)
    assert match("not udp", p)
    assert match("intranet or port 443", p)
    assert not match("intranet or proto udp", p)
    assert match("country de", p)
    assert match("region germany", p)
    assert not match("region europe", p)
    assert match("region local", pair(scope="intranet", cc=None))


def test_empty_and_errors():
    assert parse_filter("  ") is None
    for bad in ["port", "port x", "net nope", "min lots", "or tcp", "tcp or", "!", "proto foo", "region mars"]:
        with pytest.raises(FilterError):
            parse_filter(bad)
    assert parse_size("2M") == 2 * 1024**2
    assert parse_size("1.5kb/s") == 1536
