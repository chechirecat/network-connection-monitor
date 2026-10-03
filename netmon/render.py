"""Draw intranet/internet panes of nested treemap boxes onto a character canvas."""

from __future__ import annotations

import colorsys
import math
from dataclasses import dataclass

from rich.color import Color
from rich.segment import Segment
from rich.style import Style
from textual.strip import Strip

from .classify import INTERNET, INTRANET
from .packets import TCP, UDP
from .focus import LEVEL_ALL, LEVEL_SERVER, client_key, group_key, hint_labels
from .geo import EASTERN, EUROPE, GERMANY, LOCAL, REGION_LABELS, REST, UNKNOWN, WESTERN
from .treemap import Rect, fit_layout
from .views import ClientView, GroupView, service_name, weight

COLOR_RATE = "rate"
COLOR_PROTO = "proto"
COLOR_SERVICE = "service"
COLOR_GEO = "geo"

SCALE_LINEAR = "linear"
SCALE_SQRT = "sqrt"
SCALE_LOG = "log"

BG = (18, 18, 24)
PANE_COLORS = {INTRANET: (185, 185, 205), INTERNET: (120, 200, 230)}
PROTO_COLORS = {TCP: (60, 120, 220), UDP: (50, 170, 90)}
OTHER_PROTO_COLOR = (190, 90, 190)
HEAT = [
    (0.00, (35, 45, 80)),
    (0.30, (25, 95, 140)),
    (0.50, (20, 140, 110)),
    (0.70, (190, 170, 40)),
    (0.85, (220, 110, 30)),
    (1.00, (215, 40, 40)),
]

REGION_COLORS = {
    GERMANY: (50, 165, 75),
    EUROPE: (55, 105, 215),
    WESTERN: (215, 185, 35),
    EASTERN: (235, 115, 25),
    REST: (205, 45, 45),
    LOCAL: (95, 125, 135),
    UNKNOWN: (115, 115, 125),
}
LEGEND_ORDER = (GERMANY, EUROPE, WESTERN, EASTERN, REST, UNKNOWN)

ROUND = "╭╮╰╯─│"
HEAVY = "┏┓┗┛━┃"

# Smallest boxes that still show a readable label: a server box needs its title
# plus two client rows; a client box needs an IPv4 address and the rate line.
GROUP_MIN_W, GROUP_MIN_H = 18, 4
CLIENT_MIN_W, CLIENT_MIN_H = 14, 2


def fmt_bytes(n: float) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1000 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" or n >= 100 else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def fmt_rate(n: float) -> str:
    return fmt_bytes(n) + "/s"


def _lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def heat(t: float) -> tuple[int, int, int]:
    t = min(max(t, 0.0), 1.0)
    for (t0, c0), (t1, c1) in zip(HEAT, HEAT[1:]):
        if t <= t1:
            return _lerp(c0, c1, (t - t0) / (t1 - t0))
    return HEAT[-1][1]


def _hash_color(key: int) -> tuple[int, int, int]:
    h = (key * 0.61803398875) % 1.0
    r, g, b = colorsys.hls_to_rgb(h, 0.42, 0.55)
    return round(r * 255), round(g * 255), round(b * 255)


def _shade(c, f):
    return tuple(min(255, round(x * f)) for x in c)


def _fg_for(bg) -> tuple[int, int, int]:
    lum = 0.299 * bg[0] + 0.587 * bg[1] + 0.114 * bg[2]
    return (15, 15, 15) if lum > 150 else (240, 240, 240)


def _style(fg=None, bg=None, bold=False) -> Style:
    return Style(
        color=Color.from_rgb(*fg) if fg else None,
        bgcolor=Color.from_rgb(*bg) if bg else None,
        bold=bold,
    )


@dataclass
class RenderOptions:
    metric: str = "rate"
    color: str = COLOR_GEO
    scale: str = SCALE_SQRT
    panes: tuple[str, ...] = (INTRANET, INTERNET)
    level: int = LEVEL_ALL
    selected: tuple | None = None  # focus.group_key / client_key / ("p", scope)
    hints: bool = False  # overlay A..Z labels on selectable boxes


@dataclass
class Hit:
    rect: Rect
    group: GroupView | None
    client: ClientView | None = None
    others: int = 0
    pane: str | None = None  # set for a pane's title bar

    @property
    def key(self) -> tuple | None:
        """Selection key, or None for boxes that cannot be zoomed into ("+N more")."""
        if self.pane is not None:
            return ("p", self.pane)
        if self.others or self.group is None:
            return None
        return client_key(self.client) if self.client is not None else group_key(self.group)


class Canvas:
    def __init__(self, w: int, h: int) -> None:
        self.w, self.h = w, h
        base = _style(bg=BG)
        self.chars = [[" "] * w for _ in range(h)]
        self.styles = [[base] * w for _ in range(h)]

    def text(self, x: int, y: int, s: str, style: Style, max_w: int | None = None) -> None:
        if not 0 <= y < self.h:
            return
        if max_w is not None:
            s = _ellipsize(s, max_w)
        row_c, row_s = self.chars[y], self.styles[y]
        for i, ch in enumerate(s):
            xi = x + i
            if 0 <= xi < self.w:
                row_c[xi] = ch
                row_s[xi] = style

    def fill(self, r: Rect, style: Style, ch: str = " ") -> None:
        for y in range(max(r.y, 0), min(r.y + r.h, self.h)):
            for x in range(max(r.x, 0), min(r.x + r.w, self.w)):
                self.chars[y][x] = ch
                self.styles[y][x] = style

    def box(self, r: Rect, style: Style, chars: str = ROUND) -> None:
        if r.w < 2 or r.h < 2:
            return
        tl, tr, bl, br, hz, vt = chars
        x2, y2 = r.x + r.w - 1, r.y + r.h - 1
        self.text(r.x, r.y, tl + hz * (r.w - 2) + tr, style)
        self.text(r.x, y2, bl + hz * (r.w - 2) + br, style)
        for y in range(r.y + 1, y2):
            self.text(r.x, y, vt, style)
            self.text(x2, y, vt, style)

    def strips(self) -> list[Strip]:
        out = []
        for row_c, row_s in zip(self.chars, self.styles):
            segs = []
            start = 0
            for x in range(1, self.w + 1):
                if x == self.w or row_s[x] is not row_s[start]:
                    segs.append(Segment("".join(row_c[start:x]), row_s[start]))
                    start = x
            out.append(Strip(segs, self.w))
        return out


def _ellipsize(s: str, w: int) -> str:
    if w <= 0:
        return ""
    return s if len(s) <= w else s[: w - 1] + "…"


class Painter:
    """Renders grouped traffic for one frame and records hit regions for the mouse."""

    def __init__(self, groups: list[GroupView], opts: RenderOptions) -> None:
        self.groups = groups
        self.opts = opts
        self.hits: list[Hit] = []
        ws = [weight(c, opts.metric) for g in groups for c in g.clients]
        self.client_max = max(ws, default=0.0)
        self.group_max = max((weight(g, opts.metric) for g in groups), default=0.0)

    def size_of(self, item: GroupView | ClientView) -> float:
        """Layout weight: the metric, compressed by the scale so small boxes stay readable."""
        return self.scaled(weight(item, self.opts.metric))

    def scaled(self, w: float) -> float:
        if self.opts.scale == SCALE_SQRT:
            return math.sqrt(w)
        if self.opts.scale == SCALE_LOG:
            return math.log1p(w)
        return w

    def _merge(self, raw: list[float]):
        """The "others" box is sized like one item carrying all the leftover traffic."""
        return lambda idx: self.scaled(sum(raw[i] for i in idx))

    # -- colours ---------------------------------------------------------
    def _t(self, value: float, vmax: float) -> float:
        return math.log1p(value) / math.log1p(vmax) if vmax > 0 else 0.0

    def group_color(self, g: GroupView):
        if self.opts.color == COLOR_GEO:
            return _shade(REGION_COLORS[g.region], 1.2)
        if self.opts.color == COLOR_PROTO:
            protos = g.protos
            return PROTO_COLORS.get(next(iter(protos)), OTHER_PROTO_COLOR) if len(protos) == 1 else (200, 200, 200)
        if self.opts.color == COLOR_SERVICE:
            return _shade(_hash_color(g.lowest_port), 1.5)
        return _shade(heat(self._t(weight(g, self.opts.metric), self.group_max)), 1.25)

    def client_color(self, g: GroupView, c: ClientView):
        if self.opts.color == COLOR_GEO:
            # hue = distance region, brightness = traffic
            t = self._t(weight(c, self.opts.metric), self.client_max)
            return _shade(REGION_COLORS[c.region], 0.45 + 0.55 * t)
        if self.opts.color == COLOR_PROTO:
            protos = g.protos
            return _shade(PROTO_COLORS.get(next(iter(protos)), OTHER_PROTO_COLOR), 0.7) if len(protos) == 1 else (80, 80, 90)
        if self.opts.color == COLOR_SERVICE:
            return _hash_color(g.lowest_port)
        return heat(self._t(weight(c, self.opts.metric), self.client_max))

    # -- drawing ---------------------------------------------------------
    def paint(self, w: int, h: int) -> Canvas:
        canvas = Canvas(w, h)
        panes = self.opts.panes
        if not panes or w < 4 or h < 3:
            return canvas
        if self.opts.level >= LEVEL_SERVER:
            full = Rect(0, 0, w, h)
            if self.groups:
                self.draw_group(canvas, full, self.groups[0], zoomed=True)
            else:
                msg = "no traffic for this server any more (idle pairs expire) — Esc to go back"
                canvas.text(max((w - len(msg)) // 2, 0), h // 2, msg, _style(fg=(150, 150, 160), bg=BG), w)
            last = full
        else:
            rects = self._pane_rects(Rect(0, 0, w, h), len(panes))
            for scope, r in zip(panes, rects):
                self.draw_pane(canvas, r, scope)
            last = rects[-1]
        if self.opts.color == COLOR_GEO:
            self.draw_legend(canvas, last)
        self.draw_selection(canvas)
        if self.opts.hints:
            self.draw_hints(canvas)
        return canvas

    # -- selection and hints -------------------------------------------------
    def selectables(self) -> list[Hit]:
        """Boxes that can be selected/zoomed at the current level, in drawing order."""
        if self.opts.level >= LEVEL_SERVER:
            return [h for h in self.hits if h.client is not None]
        items = [h for h in self.hits if h.key is not None and h.client is None]
        return sorted(items, key=lambda h: h.pane is None)  # pane titles get the first letters

    def hint_map(self) -> dict[str, Hit]:
        items = self.selectables()
        return dict(zip(hint_labels(len(items)), items))

    def is_selected(self, key: tuple) -> bool:
        return self.opts.selected == key

    def draw_selection(self, canvas: Canvas) -> None:
        """Pane titles get a marker; server and client boxes draw their own highlight."""
        sel = self.opts.selected
        if sel and sel[0] == "p":
            hit = next((h for h in self.hits if h.pane == sel[1]), None)
            if hit is not None:
                canvas.text(hit.rect.x, hit.rect.y, "▶", _style(fg=(255, 255, 255), bg=BG, bold=True))

    def draw_hints(self, canvas: Canvas) -> None:
        # labels sit on the box corner / border so they never hide the title
        style = _style(fg=(0, 0, 0), bg=(255, 220, 60), bold=True)
        for label, h in self.hint_map().items():
            canvas.text(h.rect.x, h.rect.y, label, style)

    @staticmethod
    def _pane_rects(r: Rect, n: int) -> list[Rect]:
        if n == 1:
            return [r]
        if r.w >= 80 or r.w >= r.h * 2:  # side by side: intranet left, internet right
            a = r.w // 2
            return [Rect(r.x, r.y, a, r.h), Rect(r.x + a, r.y, r.w - a, r.h)]
        a = r.h // 2
        return [Rect(r.x, r.y, r.w, a), Rect(r.x, r.y + a, r.w, r.h - a)]

    def draw_legend(self, canvas: Canvas, r: Rect) -> None:
        """Region colour key, right-aligned in the bottom border of the last pane."""
        entries = [(REGION_COLORS[k], REGION_LABELS[k]) for k in LEGEND_ORDER]
        width = sum(len(label) + 3 for _, label in entries) + 1
        if width > r.w - 4:
            entries = [(c, label.split()[0][:4]) for c, label in entries]
            width = sum(len(label) + 3 for _, label in entries) + 1
            if width > r.w - 4:
                return
        x = r.x + r.w - 2 - width
        y = r.y + r.h - 1
        canvas.text(x, y, " ", _style(bg=BG))
        x += 1
        for color, label in entries:
            canvas.text(x, y, "■", _style(fg=color, bg=BG))
            canvas.text(x + 1, y, f" {label} ", _style(fg=(200, 200, 210), bg=BG))
            x += len(label) + 3

    def draw_pane(self, canvas: Canvas, r: Rect, scope: str) -> None:
        groups = [g for g in self.groups if g.scope == scope]
        color = PANE_COLORS[scope]
        border = _style(fg=color, bg=BG)
        canvas.box(r, border, HEAVY)
        n_clients = len({c.ip for g in groups for c in g.clients})
        up = sum(g.rate_up for g in groups)
        down = sum(g.rate_down for g in groups)
        total = sum(g.total for g in groups)
        title = (
            f" {scope.upper()} ┃ {len(groups)} servers · {n_clients} clients · "
            f"↑{fmt_rate(up)} ↓{fmt_rate(down)} · Σ{fmt_bytes(total)} "
        )
        canvas.text(r.x + 2, r.y, title, _style(fg=color, bg=BG, bold=True), r.w - 4)
        if self.opts.level == LEVEL_ALL:
            self.hits.append(Hit(Rect(r.x + 1, r.y, min(len(title) + 2, r.w - 2), 1), None, pane=scope))
        inner = r.inset(1)
        if inner.w <= 0 or inner.h <= 0:
            return
        weights = [self.size_of(g) for g in groups]
        kept, dropped, rects, others = fit_layout(
            weights, inner, GROUP_MIN_W, GROUP_MIN_H, self._merge([weight(g, self.opts.metric) for g in groups])
        )
        if not kept and others is None:
            msg = "no traffic" if not groups else f"{len(groups)} idle servers"
            canvas.text(inner.x + max((inner.w - len(msg)) // 2, 0), inner.y + inner.h // 2, msg,
                        _style(fg=(110, 110, 120), bg=BG), inner.w)
            return
        for i, gr in zip(kept, rects):
            if gr.area:
                self.draw_group(canvas, gr, groups[i])
        if others is not None and others.area:
            self.draw_others(canvas, others, [groups[i] for i in dropped if weights[i] > 0])

    def draw_others(self, canvas: Canvas, r: Rect, groups: list[GroupView], parent: GroupView | None = None,
                    count: int | None = None) -> None:
        style = _style(fg=(190, 190, 200), bg=(45, 45, 55))
        canvas.fill(r, style, "░")
        n = len(groups) if count is None else count
        noun = "servers" if parent is None else "clients"
        label = next((s for s in (f"+{n} more {noun}", f"+{n} more", f"+{n}") if len(s) <= r.w), f"+{n}")
        canvas.text(r.x, r.y + (r.h // 2 if parent is None else 0), label, style, r.w)
        self.hits.append(Hit(r, parent, None, n))

    def draw_group(self, canvas: Canvas, r: Rect, g: GroupView, zoomed: bool = False) -> None:
        color = self.group_color(g)
        self.hits.append(Hit(r, g))
        if r.w < 4 or r.h < 3:
            style = _style(fg=_fg_for(color), bg=color)
            canvas.fill(r, style)
            canvas.text(r.x, r.y, g.label, style, r.w)
            return
        selected = not zoomed and self.is_selected(group_key(g))
        if selected:
            color = (255, 255, 255)
        border = _style(fg=color, bg=BG, bold=selected)
        canvas.box(r, border, HEAVY if selected else ROUND)
        geo = f"{g.cc} " if g.server_is_remote and g.cc else ""
        title = f" {geo}{g.label} {g.services} "
        rate = f" {fmt_rate(g.rate)} " if self.opts.metric == "rate" else f" {fmt_bytes(g.total)} "
        canvas.text(r.x + 1, r.y, title, _style(fg=color, bg=BG, bold=True), r.w - 2)
        if r.w - 2 > len(title) + len(rate):
            canvas.text(r.x + r.w - 1 - len(rate), r.y, rate, _style(fg=color, bg=BG), len(rate))
        if r.w > len(g.server) + 4 and g.name:
            canvas.text(r.x + 1, r.y + r.h - 1, f" {g.server} ", _style(fg=_shade(color, 0.7), bg=BG), r.w - 2)

        inner = r.inset(1)
        weights = [self.size_of(c) for c in g.clients]
        min_w, min_h = (CLIENT_MIN_W + 8, CLIENT_MIN_H + 3) if zoomed else (CLIENT_MIN_W, CLIENT_MIN_H)
        kept, dropped, rects, others = fit_layout(
            weights, inner, min_w, min_h, self._merge([weight(c, self.opts.metric) for c in g.clients])
        )
        if not kept and others is None:
            canvas.text(inner.x, inner.y, f"{len(g.clients)} idle", _style(fg=(110, 110, 120), bg=BG), inner.w)
            return
        hidden = sum(1 for i in dropped if weights[i] > 0)
        for i, cr in zip(kept, rects):
            if cr.area:
                self.draw_client(canvas, cr, g, g.clients[i], hidden if others is None else 0, zoomed)
        if others is not None and others.area:
            self.draw_others(canvas, others, [], parent=g, count=hidden)

    def draw_client(
        self, canvas: Canvas, r: Rect, g: GroupView, c: ClientView, hidden: int = 0, zoomed: bool = False
    ) -> None:
        bg = self.client_color(g, c)
        fg = _fg_for(bg)
        style = _style(fg=fg, bg=bg)
        canvas.fill(r, style)
        self.hits.append(Hit(r, g, c))
        framed = zoomed and self.is_selected(client_key(c)) and r.w >= 6 and r.h >= 3
        if framed:
            canvas.box(r, _style(fg=(255, 255, 255), bg=bg, bold=True), HEAVY)
            r = r.inset(1)  # text goes inside the highlight frame
        else:
            # a darker right/bottom edge separates neighbouring boxes of similar colour
            edge = _style(fg=_shade(bg, 0.55), bg=bg)
            if r.w >= 6:
                for y in range(r.y, r.y + r.h):
                    canvas.text(r.x + r.w - 1, y, "▕", edge)
            if r.h >= 3:
                canvas.text(r.x, r.y + r.h - 1, "▁" * (r.w - (1 if r.w >= 6 else 0)), edge)
        tw = r.w - (1 if r.w >= 6 and not framed else 0)
        inbound = c.remote == c.ip
        lines = [c.label + (f" {c.cc}" if inbound and c.cc else "")]
        if c.name:
            lines.append(c.ip)
        lines.append(f"↑{fmt_rate(c.rate_up)} ↓{fmt_rate(c.rate_down)}")
        lines.append(f"Σ{fmt_bytes(c.total)} · {c.conns} conn")
        if hidden:
            lines.insert(1, f"+{hidden} more clients")
        if zoomed:
            if len(g.ports) > 1:
                lines.append("→ " + ", ".join(service_name(p, pr) for p, pr in sorted(
                    c.services, key=lambda s: (s[0] or -1, s[1]))))
            if c.ports:
                lines.append("ports " + " ".join(str(p) for p in sorted(c.ports)))
        rows = r.h - (1 if r.h >= 3 and not framed else 0)
        if rows < len(lines) and c.name:
            lines.remove(c.ip)
        for i, line in enumerate(lines[: max(rows, 1)]):
            canvas.text(r.x, r.y + i, line, _style(fg=fg, bg=bg, bold=i == 0), tw)

    def hit(self, x: int, y: int) -> Hit | None:
        # client hits are appended after their group, so search from the end
        for h in reversed(self.hits):
            if h.rect.contains(x, y):
                return h
        return None


def _geo_text(cc: str | None, region: str) -> str:
    if region == LOCAL:
        return "local"
    return f"{cc or '??'}, {REGION_LABELS[region]}"


def describe(hit: Hit | None, metric: str) -> str:
    if hit is None:
        return ""
    if hit.pane is not None:
        return f"{hit.pane} — Enter or double-click to zoom in"
    if hit.group is None:
        return f"{hit.others} smaller servers not shown — filter, use `v` for one pane, or `l` for log scale"
    g = hit.group
    head = (
        f"{g.scope} server {g.label}" + (f" ({g.server})" if g.name else "")
        + f" [{g.services}] {_geo_text(g.cc, g.region)}"
    )
    if hit.client is None and hit.others:
        return f"{head} — {hit.others} smaller clients"
    if hit.client is None:
        return (
            f"{head} — {len(g.clients)} clients, {g.conns} conn, "
            f"↑{fmt_rate(g.rate_up)} ↓{fmt_rate(g.rate_down)}, Σ{fmt_bytes(g.total)}"
        )
    c = hit.client
    name = c.label + (f" ({c.ip})" if c.name else "")
    if c.remote == c.ip:
        name += f" [{_geo_text(c.cc, c.region)}]"
    return (
        f"{name} → {head} — {c.conns} conn, ↑{fmt_rate(c.rate_up)} ↓{fmt_rate(c.rate_down)}, "
        f"Σ↑{fmt_bytes(c.up)} Σ↓{fmt_bytes(c.down)}"
    )
