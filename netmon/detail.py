"""Text views: the client-level detail page, traffic graphs and dump lines."""

from __future__ import annotations

import time

from rich.markup import escape
from rich.text import Text

from .geo import LOCAL, REGION_LABELS, region_of
from .model import DumpEntry, PairView
from .packets import TCP, flags_text, proto_name
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


def detail_markup(
    pairs: list[PairView],
    names: NameLookup,
    now: float,
    history: list[tuple[float, float]] | None = None,
    width: int = 80,
    hostnames=None,
) -> str:
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
    if hostnames is not None:
        lines += [""] + names_markup(first, hostnames, names)
    if history:
        lines += [""] + history_markup(history, max(width - 4, 10))
    lines += ["", "  [dim]Esc / Backspace: back · 2: connections · 3: packet dump[/]"]
    return "\n".join(lines)


def names_markup(pair: PairView, hostnames, names: NameLookup) -> list[str]:
    """Which names point at the server, and where each was learned."""
    infos = hostnames.names(pair.server)
    ptr = names(pair.server) if not infos else None
    lines = ["  [b]names for the server[/]"]
    if not infos and not ptr:
        lines.append("  [dim]none learned yet — names come from TLS ClientHellos (SNI) and DNS answers of new "
                     "connections; QUIC, DNS-over-HTTPS and ECH hide them[/]")
    for i in infos[:8]:
        lines.append(f"  {escape(i.name):<40} [dim]{i.source}, seen {i.count}×[/]")
    if len(infos) > 8:
        lines.append(f"  [dim]+{len(infos) - 8} more[/]")
    if ptr:
        lines.append(f"  {escape(ptr):<40} [dim]reverse DNS[/]")
    if len([i for i in infos if i.source != "TLS ECH (decoy)"]) > 1:
        lines.append("  [dim]several sites share this address (typical for CDNs such as Cloudflare)[/]")
    return lines


BLOCKS = " ▁▂▃▄▅▆▇█"


def bar_chart(values: list[float], width: int, height: int) -> list[str]:
    """Rows (top first) of a bar chart of the last ``width`` values, using eighth blocks."""
    values = values[-width:]
    vmax = max(values, default=0.0)
    rows = []
    for row in range(height - 1, -1, -1):
        line = []
        for v in values:
            eighths = round(v / vmax * height * 8) if vmax > 0 else 0
            line.append(BLOCKS[min(max(eighths - row * 8, 0), 8)])
        rows.append("".join(line).rjust(width))
    return rows


def history_markup(history: list[tuple[float, float]], width: int, height: int = 3) -> list[str]:
    """Upload and download graphs (newest sample on the right), one second per column."""
    out = []
    for label, color, values in (
        ("↑ up", "cyan", [h[0] for h in history]),
        ("↓ down", "dark_orange", [h[1] for h in history]),
    ):
        peak = max(values, default=0.0)
        out.append(f"  [b]{label}[/]  peak {fmt_rate(peak)} · last {len(values[-width:])}s")
        out += [f"  [{color}]{row}[/]" for row in bar_chart(values, width, height)]
    return out


def dump_text(e: DumpEntry, show_payload: bool) -> Text:
    """One dump entry as Rich Text (plus a hex dump when payload bytes were captured)."""
    p = e.packet
    ts = time.strftime("%H:%M:%S", time.localtime(e.time)) + f".{int(e.time * 1000) % 1000:03d}"
    src = f"{p.src}:{p.sport}" if p.sport is not None else p.src
    dst = f"{p.dst}:{p.dport}" if p.dport is not None else p.dst
    t = Text()
    t.append(ts + "  ", style="dim")
    t.append(f"{src} → {dst}", style="cyan" if e.up else "dark_orange")
    t.append(f"  {proto_name(p.proto)}")
    if p.proto == TCP:
        t.append(f" [{flags_text(p.tcp_flags) or '-'}]", style="bold")
        if p.seq is not None:
            t.append(f" seq {p.seq}", style="dim")
        if p.ack and p.ack_no is not None:
            t.append(f" ack {p.ack_no}", style="dim")
    t.append(f"  len {p.payload_len}  ({p.length} B)")
    if show_payload and p.payload:
        for off in range(0, len(p.payload), 16):
            chunk = p.payload[off : off + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            t.append(f"\n      {off:04x}  {hexpart:<47}  {asc}", style="grey62")
    return t
