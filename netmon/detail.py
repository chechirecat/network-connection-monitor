"""Text for the deepest zoom level: one client talking to one server."""

from __future__ import annotations

from rich.markup import escape

from .geo import LOCAL, REGION_LABELS, region_of
from .model import PairView
from .render import fmt_bytes, fmt_rate
from .views import NameLookup, service_name


def _ago(seconds: float) -> str:
    seconds = max(int(seconds), 0)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"


def _endpoint(ip: str, names: NameLookup) -> str:
    name = names(ip)
    return f"[b]{escape(name)}[/] ({ip})" if name else f"[b]{ip}[/]"


def detail_markup(pairs: list[PairView], names: NameLookup, now: float) -> str:
    """Rich markup describing the given pairs (all between one client and one server)."""
    if not pairs:
        return "\n  [dim]No traffic between these hosts any more (idle pairs expire). Esc to go back.[/]"
    first = pairs[0]
    remote_cc = first.remote_cc
    region = region_of(remote_cc) if first.remote else LOCAL
    where = "local network" if region == LOCAL else f"{remote_cc or '??'} · {REGION_LABELS[region]}"
    remote_side = "server" if first.remote == first.server else "client" if first.remote else None
    up = sum(p.up for p in pairs)
    down = sum(p.down for p in pairs)
    lines = [
        "",
        f"  client  {_endpoint(first.client, names)}",
        f"  server  {_endpoint(first.server, names)}",
        "",
        f"  scope     {first.scope}" + (f" — remote end is the {remote_side}" if remote_side else ""),
        f"  location  {where}",
        f"  rate      ↑ {fmt_rate(sum(p.rate_up for p in pairs))}   ↓ {fmt_rate(sum(p.rate_down for p in pairs))}",
        f"  total     ↑ {fmt_bytes(up)}   ↓ {fmt_bytes(down)}   ({sum(p.packets for p in pairs)} packets)",
        f"  active    {_ago(now - min(p.first_seen for p in pairs))}, "
        f"last packet {_ago(now - max(p.last_seen for p in pairs))} ago",
        "",
        "  [b]service            conns   ↑ /s        ↓ /s        Σ           client ports[/]",
    ]
    for p in sorted(pairs, key=lambda p: -p.total):
        ports = " ".join(str(x) for x in sorted(p.client_ports)[:12])
        if len(p.client_ports) > 12:
            ports += f" +{len(p.client_ports) - 12}"
        lines.append(
            f"  {service_name(p.port, p.proto):<18} {p.conns:>5}   {fmt_rate(p.rate_up):<10}  "
            f"{fmt_rate(p.rate_down):<10}  {fmt_bytes(p.total):<10}  {ports}"
        )
    lines += ["", "  [dim]Esc / Backspace: back · t: table[/]"]
    return "\n".join(lines)
