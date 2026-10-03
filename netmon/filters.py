"""Filter expressions applied to client/server pairs.

Grammar (case-insensitive)::

    expr  := conj ("or" conj)*
    conj  := term+                      # terms are AND-ed
    term  := ["!" | "not"] atom
    atom  := host X | server X | client X | net CIDR | port N | proto P
           | min SIZE                   # minimum rate, e.g. 10k, 2M
           | country CC                 # country of the remote end, e.g. de, us
           | region R                   # germany, europe, western, eastern, rest, local, unknown
           | internet | intranet | tcp | udp | icmp
           | TEXT                       # substring of an ip, hostname or service

Examples: ``port 443 !host 10.0.0.1``, ``internet min 100k``, ``ssh or dns``,
``!region germany``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable

from .classify import INTERNET, INTRANET
from .geo import LOCAL, REGION_LABELS, region_of
from .model import PairView
from .packets import PROTO_NAMES
from .views import NameLookup, service_name

Pred = Callable[[PairView, NameLookup], bool]

_ARG_KEYWORDS = {"host", "server", "client", "net", "port", "proto", "min", "country", "region"}
_PROTO_NUMBERS = {name: num for num, name in PROTO_NAMES.items()}


class FilterError(ValueError):
    pass


def parse_size(text: str) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?(?:/s)?", text.strip().lower())
    if not m:
        raise FilterError(f"bad size: {text!r} (try 10k, 2M)")
    mult = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[m.group(2)]
    return float(m.group(1)) * mult


def _endpoint_matches(ip: str, needle: str, names: NameLookup) -> bool:
    if ip == needle or needle in ip:
        return True
    name = names(ip)
    return bool(name and needle in name.lower())


def _atom(keyword: str, arg: str | None) -> Pred:
    if keyword == "host":
        return lambda p, n: _endpoint_matches(p.client, arg, n) or _endpoint_matches(p.server, arg, n)
    if keyword == "server":
        return lambda p, n: _endpoint_matches(p.server, arg, n)
    if keyword == "client":
        return lambda p, n: _endpoint_matches(p.client, arg, n)
    if keyword == "net":
        try:
            net = ipaddress.ip_network(arg, strict=False)
        except ValueError as e:
            raise FilterError(str(e)) from None

        def in_net(ip: str) -> bool:
            addr = ipaddress.ip_address(ip)
            return addr.version == net.version and addr in net

        return lambda p, n: in_net(p.client) or in_net(p.server)
    if keyword == "port":
        if not arg.isdigit():
            raise FilterError(f"bad port: {arg!r}")
        port = int(arg)
        return lambda p, n: p.port == port or port in p.client_ports
    if keyword == "proto":
        num = _PROTO_NUMBERS.get(arg, int(arg) if arg.isdigit() else None)
        if num is None:
            raise FilterError(f"unknown protocol: {arg!r}")
        return lambda p, n: p.proto == num
    if keyword == "min":
        size = parse_size(arg)
        return lambda p, n: p.rate >= size
    if keyword == "country":
        cc = arg.upper()
        return lambda p, n: p.remote_cc == cc
    if keyword == "region":
        if arg not in REGION_LABELS:
            raise FilterError(f"unknown region {arg!r}: {', '.join(REGION_LABELS)}")
        return lambda p, n: (region_of(p.remote_cc) if p.remote else LOCAL) == arg
    if keyword in (INTERNET, INTRANET):
        return lambda p, n: p.scope == keyword
    if keyword in _PROTO_NUMBERS:
        num = _PROTO_NUMBERS[keyword]
        return lambda p, n: p.proto == num
    text = keyword
    return lambda p, n: (
        _endpoint_matches(p.client, text, n)
        or _endpoint_matches(p.server, text, n)
        or text in service_name(p.port, p.proto)
    )


def parse_filter(text: str) -> Pred | None:
    """Compile a filter expression. Returns None for an empty filter."""
    tokens = text.lower().split()
    if not tokens:
        return None
    alternatives: list[list[Pred]] = [[]]
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if tok == "or":
            if not alternatives[-1]:
                raise FilterError("'or' needs a term on both sides")
            alternatives.append([])
            continue
        negate = False
        if tok in ("!", "not"):
            negate = True
            if i >= len(tokens):
                raise FilterError(f"'{tok}' needs a term")
            tok = tokens[i]
            i += 1
        elif tok.startswith("!") and len(tok) > 1:
            negate, tok = True, tok[1:]
        arg = None
        if tok in _ARG_KEYWORDS:
            if i >= len(tokens):
                raise FilterError(f"'{tok}' needs an argument")
            arg = tokens[i]
            i += 1
        pred = _atom(tok, arg)
        if negate:
            pred = (lambda f: lambda p, n: not f(p, n))(pred)
        alternatives[-1].append(pred)
    if not alternatives[-1]:
        raise FilterError("'or' needs a term on both sides")
    return lambda p, n: any(all(t(p, n) for t in conj) for conj in alternatives)
