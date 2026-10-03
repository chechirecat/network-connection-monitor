"""Textual UI."""

from __future__ import annotations

import time
from dataclasses import replace

from rich.markup import escape
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.strip import Strip
from textual.widget import Widget
from textual.widgets import DataTable, Footer, Input, RichLog, Static

from .classify import INTERNET, INTRANET
from .detail import _ago, chunk_text, detail_markup, dump_text, stream_header_markup
from .focus import LEVEL_ALL, LEVEL_CLIENT, LEVEL_SERVER, Focus, nearest
from .filters import FilterError, parse_filter
from .model import PairView, TrafficModel
from .packets import TCP, proto_name
from .geo import MAX_AGE_DAYS, REGION_LABELS, GeoDB
from .hostnames import HostNames
from .render import (
    COLOR_GEO,
    COLOR_PROTO,
    COLOR_RATE,
    COLOR_SERVICE,
    SCALE_LINEAR,
    SCALE_LOG,
    SCALE_SQRT,
    Painter,
    RenderOptions,
    describe,
    fmt_bytes,
    fmt_rate,
)
from .resolver import Resolver
from .sources import Source
from .stream import StreamFollower
from .views import (
    GROUP_HOST,
    GROUP_SERVICE,
    METRIC_RATE,
    METRIC_TOTAL,
    SORT_KEYS,
    build_groups,
    service_name,
    sort_groups,
)

COLOR_MODES = (COLOR_GEO, COLOR_RATE, COLOR_PROTO, COLOR_SERVICE)
SCALES = (SCALE_SQRT, SCALE_LOG, SCALE_LINEAR)
PAYLOAD_BYTES = 64
PANE_CYCLE = (None, INTRANET, INTERNET)  # `v`: all → intranet → internet
ARROWS = {"left": "left", "right": "right", "up": "up", "down": "down"}


def _geo_cell(cc: str | None, region: str) -> str:
    return "local" if region == "local" else f"{cc or '??'} {REGION_LABELS[region]}"


class TreemapView(Widget):
    """Renders the panes; cached per frame and re-painted on data or size change."""

    can_focus = True

    def __init__(self) -> None:
        super().__init__()
        self.groups = []
        self.opts = RenderOptions()
        self._painter: Painter | None = None
        self._strips: list[Strip] = []
        self._painted_size = (0, 0)
        self._stale = True

    def show(self, groups, opts: RenderOptions) -> None:
        self.groups, self.opts = groups, opts
        self._stale = True
        self.refresh()

    def _ensure(self) -> None:
        size = (self.size.width, self.size.height)
        if self._stale or size != self._painted_size:
            self._painter = Painter(self.groups, self.opts)
            self._strips = self._painter.paint(*size).strips()
            self._painted_size = size
            self._stale = False

    def render_line(self, y: int) -> Strip:
        self._ensure()
        return self._strips[y] if y < len(self._strips) else Strip.blank(self.size.width)

    @property
    def painter(self) -> Painter | None:
        self._ensure()
        return self._painter

    def describe_at(self, x: int, y: int) -> str:
        return describe(self.painter.hit(x, y), self.opts.metric) if self.painter else ""

    def on_click(self, event: events.Click) -> None:
        hit = self.painter.hit(event.x, event.y) if self.painter else None
        selectable = {id(h) for h in self.painter.selectables()} if self.painter else set()
        # a click inside a client box at the overview levels selects its server box
        while hit is not None and id(hit) not in selectable and hit.client is not None:
            hit = next((h for h in self.painter.selectables() if h.group is hit.group), None)
        if hit is None or id(hit) not in selectable:
            return
        self.app.select(hit.key)
        if event.chain >= 2:
            self.app.zoom_into(hit)

    def on_key(self, event: events.Key) -> None:
        # while letter hints are shown, letters pick a box instead of running shortcuts
        if self.app.hints and event.character and event.character.isalpha():
            event.prevent_default()
            event.stop()
            self.app.hint_key(event.character.upper())

    def on_mouse_move(self, event: events.MouseMove) -> None:
        self.app.hover(self.describe_at(event.x, event.y))

    def on_leave(self, event: events.Leave) -> None:
        self.app.hover("")


class NetMonApp(App):
    TITLE = "netmon"
    AUTO_FOCUS = "TreemapView"
    CSS = """
    Screen { background: rgb(18,18,24); }
    TreemapView { height: 1fr; }
    #table { height: 1fr; display: none; }
    #detail { height: 1fr; display: none; }
    #conns { height: 1fr; display: none; }
    #dump { height: 1fr; display: none; background: rgb(18,18,24); }
    #stream-head { height: auto; display: none; background: rgb(28,28,38); padding: 0 0 1 0; }
    #stream { height: 1fr; display: none; background: rgb(18,18,24); }
    #crumbs { height: 1; background: rgb(40,40,55); padding: 0 1; }
    #filter { dock: bottom; display: none; }
    #hover { height: 1; color: $text-muted; background: rgb(30,30,40); padding: 0 1; }
    #status { height: 1; background: rgb(40,40,55); padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "filter", "Filter"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("r", "reverse", "Reverse"),
        Binding("m", "cycle_metric", "Size"),
        Binding("l", "cycle_scale", "Scale"),
        Binding("c", "cycle_color", "Color"),
        Binding("g", "toggle_group", "Group"),
        Binding("v", "cycle_panes", "Panes"),
        Binding("space", "toggle_hints", "Letters"),
        Binding("enter", "zoom_in", "Zoom", show=False),
        Binding("backspace", "zoom_out", "Back"),
        Binding("1", "view('map')", "Map"),
        Binding("2", "view('conns')", "Conns"),
        Binding("3", "view('dump')", "Dump"),
        Binding("4", "view('stream')", "Stream"),
        Binding("f", "follow", "Follow", show=False),
        Binding("h", "toggle_hex", "Hex", show=False),
        Binding("t", "toggle_table", "Table"),
        Binding("x", "toggle_payload", "Payload"),
        Binding("p", "pause", "Pause"),
        Binding("z", "reset", "Reset Σ"),
        Binding("escape", "escape", "Back", show=False),
        *(Binding(k, f"move('{d}')", show=False) for k, d in ARROWS.items()),
    ]

    def __init__(
        self,
        source: Source,
        model: TrafficModel,
        resolver: Resolver,
        geo: GeoDB | None = None,
        interval: float = 1.0,
        hostnames: HostNames | None = None,
    ) -> None:
        super().__init__()
        self.hostnames = hostnames or HostNames(enabled=False)
        self.follower = StreamFollower()
        source.sniff = self._sniff
        self.geo = geo
        self._geo_state = geo.state if geo else None
        self.source = source
        self.model = model
        self.resolver = resolver
        self.interval = interval
        self.pairs: list[PairView] = []
        self.paused = False
        self.sort_key = "size"
        self.sort_reverse = False
        self.metric = METRIC_RATE
        self.color = COLOR_GEO
        self.scale = SCALE_SQRT
        self.group_mode = GROUP_HOST
        self.focus_path = Focus()
        self.selected: tuple | None = None
        self.hints = False
        self._hint_buffer = ""
        self._table_targets: list[Focus] = []
        self._conn_targets: list[Focus] = []
        self.view = "map"  # map | table | conns | dump | stream
        self._dump_seq = 0
        self._conn_rows: list = []
        self._stream_seq = 0
        self._stream_last: tuple | None = None  # (up, time) of the last data chunk shown
        self.hex_mode = False
        self.filter_text = ""
        self.filter_pred = None
        self.filter_error = ""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="crumbs")
            yield TreemapView()
            yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
            yield DataTable(id="conns", zebra_stripes=True, cursor_type="row")
            yield RichLog(id="dump", max_lines=20000, wrap=False)
            yield Static(id="stream-head")
            yield RichLog(id="stream", max_lines=50000, wrap=True)
            yield Static(id="detail")
            yield Static(id="hover")
            yield Static(id="status")
        yield Input(placeholder="filter: host/server/client X · net CIDR · port N · proto tcp · min 10k · "
                    "internet/intranet · text · ! negates · or", id="filter")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_columns("Scope", "Server", "Geo", "Services", "Clients", "Conns", "↑ /s", "↓ /s", "Σ total")
        self.query_one("#conns", DataTable).add_columns(
            "Proto", "Client", "Port", "", "Server", "Port", "Service", "Host (TLS SNI)", "State",
            "↑ /s", "↓ /s", "Σ ↑", "Σ ↓", "Pkts", "Age", "Idle",
        )
        self.update_watch()
        self.source.start(self.ingest)
        self.set_interval(self.interval, self.tick)
        self.tick()
        if self.geo and self.geo.age_days is not None and self.geo.age_days > MAX_AGE_DAYS:
            action = "updating in the background" if self.geo.will_update else "run netmon --update-geoip"
            self.notify(f"GeoIP database is {self.geo.age_days:.0f} days old — {action}",
                        title="Outdated country data", severity="warning", timeout=10)

    # -- data ------------------------------------------------------------
    def tick(self) -> None:
        try:
            self.check_geo_update()
            pairs = self.model.tick()
            if not self.paused:
                self.pairs = pairs
                self.update_view()
            else:
                self.update_status()
        except NoMatches:
            pass  # timer fired while the app is shutting down and widgets are gone

    def _sniff(self, src: str, sport: int, dst: str, dport: int) -> bool:
        """Parser callback: keep the whole payload of this packet?"""
        return self.follower.wants_payload(src, sport, dst, dport) or (
            self.hostnames.enabled and self.hostnames.wants_payload(src, sport, dst, dport)
        )

    def ingest(self, p) -> None:
        """Capture-thread sink: learn hostnames, follow the stream, then account the packet. Payload
        kept only for those is dropped (or cut to the opt-in size) before the dump can see it."""
        self.follower.observe(p)
        if p.payload:
            self.hostnames.observe(p)
            keep = self.source.payload_bytes
            if len(p.payload) > keep:
                p = replace(p, payload=p.payload[:keep])
        self.model.add(p)

    def names(self, ip: str) -> str | None:
        """Display name: learned from traffic (SNI/DNS) first, then reverse DNS."""
        return self.hostnames.best(ip) or self.resolver.name(ip)

    def update_view(self) -> None:
        names = self.names
        focus = self.focus_path
        pairs = [p for p in self.pairs if focus.matches(p)]
        if self.filter_pred:
            pairs = [p for p in pairs if self.filter_pred(p, names)]
        # zoomed into a whole host: show it as one box even when grouping by service
        mode = GROUP_HOST if focus.level >= LEVEL_SERVER and focus.service is None else self.group_mode
        groups = build_groups(pairs, mode, names)
        groups = sort_groups(groups, self.sort_key, self.metric, self.sort_reverse)
        opts = RenderOptions(
            metric=self.metric,
            color=self.color,
            scale=self.scale,
            panes=(focus.scope,) if focus.scope else (INTRANET, INTERNET),
            level=focus.level,
            selected=self.selected,
            hints=self.hints,
        )
        self.query_one(TreemapView).show(groups, opts)
        self.update_panels()
        if self.view == "table":
            self.fill_table(groups)
        elif self.view == "conns":
            self.fill_conns({(p.client, p.server, p.port, p.proto) for p in pairs})
        elif self.view == "dump":
            self.append_dump({(p.client, p.server, p.port, p.proto) for p in pairs})
        elif self.view == "stream":
            self.update_stream()
        elif focus.level == LEVEL_CLIENT:
            detail = self.query_one("#detail", Static)
            history = self.model.history(focus.matches)
            width = detail.size.width or self.size.width
            detail.update(detail_markup(pairs, names, time.monotonic(), history, width, self.hostnames))
        self.update_crumbs(groups)
        self.update_status(len(pairs))

    def update_panels(self) -> None:
        """Show exactly one of map (treemap, or detail page at client level) / table / conns / dump."""
        detail_mode = self.view == "map" and self.focus_path.level == LEVEL_CLIENT
        self.query_one("#table", DataTable).display = self.view == "table"
        self.query_one("#conns", DataTable).display = self.view == "conns"
        self.query_one("#dump", RichLog).display = self.view == "dump"
        self.query_one("#stream-head", Static).display = self.view == "stream"
        self.query_one("#stream", RichLog).display = self.view == "stream"
        self.query_one("#detail", Static).display = detail_mode
        self.query_one(TreemapView).display = self.view == "map" and not detail_mode

    def update_watch(self) -> None:
        """Record packets for the dump while zoomed into a server or client, or while the dump is open."""
        watching = self.view == "dump" or self.focus_path.level >= LEVEL_SERVER
        self.model.set_watch(self.focus_path.matches if watching else None)
        self._dump_seq = 0
        self.query_one("#dump", RichLog).clear()

    def fill_conns(self, allowed: set) -> None:
        """Connection table for the current focus; ``allowed`` = pair keys passing the filter."""
        conns = [c for c in self.model.connections(self.focus_path.matches)
                 if (c.client, c.server, c.server_port, c.proto) in allowed]
        size = (lambda c: c.rate) if self.metric == METRIC_RATE else (lambda c: c.total)
        order = {
            "name": lambda c: (c.client, c.client_port or 0),
            "port": lambda c: (c.server_port or 0, -size(c)),
        }.get(self.sort_key, lambda c: -size(c))
        conns.sort(key=order, reverse=self.sort_reverse)
        table = self.query_one("#conns", DataTable)
        row = table.cursor_row
        table.clear()
        self._conn_targets = []
        self._conn_rows = conns
        now = time.monotonic()
        names = self.names
        for c in conns:
            hello = self.hostnames.connection(c.client, c.client_port, c.server, c.server_port)
            host = (hello.sni or "") + (" (ECH decoy)" if hello.ech else "") if hello else ""
            table.add_row(
                proto_name(c.proto), names(c.client) or c.client, str(c.client_port or ""), "→",
                c.server, str(c.server_port or ""), service_name(c.server_port, c.proto), host,
                c.state, fmt_rate(c.rate_up), fmt_rate(c.rate_down), fmt_bytes(c.up), fmt_bytes(c.down),
                str(c.packets), _ago(now - c.first_seen), _ago(now - c.last_seen),
            )
            service = (c.server_port, c.proto) if self.focus_path.service or self.group_mode == GROUP_SERVICE else None
            self._conn_targets.append(Focus(scope=c.scope, server=c.server, service=service, client=c.client))
        if table.row_count:
            table.move_cursor(row=min(row, table.row_count - 1))

    # -- stream view -----------------------------------------------------------------
    def update_stream(self) -> None:
        self.follower.flush()
        head = self.query_one("#stream-head", Static)
        head.update(stream_header_markup(self.follower, self.names, head.size.width or self.size.width,
                                         self.hex_mode))
        if self.paused:
            return
        log = self.query_one("#stream", RichLog)
        chunks = self.follower.chunks_since(self._stream_seq)
        for c in chunks:
            # consecutive data in the same direction reads as one block: header only on a change
            header = c.kind != "data" or self._stream_last is None or self._stream_last[0] != c.up \
                or c.time - self._stream_last[1] > 1.0
            log.write(chunk_text(c, self.hex_mode, header, self.follower.started))
            self._stream_last = (c.up, c.time) if c.kind == "data" else None
        if chunks:
            self._stream_seq = chunks[-1].seq

    def _reset_stream_log(self) -> None:
        self._stream_seq = 0
        self._stream_last = None
        self.query_one("#stream", RichLog).clear()

    def follow(self, c) -> None:
        self.follower.follow(c.client, c.client_port, c.server, c.server_port, c.proto)
        self._reset_stream_log()

    def action_follow(self) -> None:
        """Follow the connection under the cursor in the connections view, else the busiest in focus."""
        target = None
        if self.view == "conns":
            row = self.query_one("#conns", DataTable).cursor_row
            if 0 <= row < len(self._conn_rows):
                target = self._conn_rows[row]
        if target is None:
            conns = self.model.connections(self.focus_path.matches)
            target = max(conns, key=lambda c: (c.proto == TCP, c.rate), default=None)
        if target is None:
            self.notify("No connection in focus to follow", severity="warning")
            return
        self.follow(target)
        self.action_view("stream")

    def action_toggle_hex(self) -> None:
        if self.view == "stream":
            self.hex_mode = not self.hex_mode
            self._reset_stream_log()
            self.update_view()

    def append_dump(self, allowed: set) -> None:
        if self.paused:
            return
        log = self.query_one("#dump", RichLog)
        show_payload = self.source.payload_bytes > 0
        entries = self.model.dump_since(self._dump_seq)
        for e in entries:
            if e.pair in allowed:
                log.write(dump_text(e, show_payload))
        if entries:
            self._dump_seq = entries[-1].seq

    def update_crumbs(self, groups) -> None:
        f = self.focus_path
        parts = ["All"]
        if f.scope:
            parts.append(f.scope.capitalize())
        if f.server:
            g = groups[0] if groups else None
            cc = f"{g.cc} " if g and g.server_is_remote and g.cc else ""
            label = g.label if g else (self.names(f.server) or f.server)
            svc = f" {service_name(*f.service)}" if f.service else ""
            parts.append(f"{cc}{label}{svc}")
        if f.client:
            parts.append(self.names(f.client) or f.client)
        crumbs = " › ".join(f"[b]{escape(p)}[/]" if i == len(parts) - 1 else escape(p) for i, p in enumerate(parts))
        if self.view == "stream":
            help_text = "following one connection · h hex/text · p pause · Esc back to connections"
        elif self.view == "conns":
            help_text = "Enter zoom into pair · f follow stream" + (" · Esc back" if f.level else "")
        elif self.hints:
            help_text = f"type letters to zoom{' — ' + self._hint_buffer if self._hint_buffer else ''} · Esc cancel"
        elif f.level == LEVEL_CLIENT:
            help_text = "Esc back"
        else:
            help_text = "Space letters · arrows + Enter zoom · double-click zoom" + (" · Esc back" if f.level else "")
        self.query_one("#crumbs", Static).update(f"{crumbs}   [dim]{help_text}[/]")

    def fill_table(self, groups) -> None:
        table = self.query_one("#table", DataTable)
        row = table.cursor_row
        table.clear()
        self._table_targets = []
        focus = self.focus_path
        for g in groups:
            server = g.label + (f" ({g.server})" if g.name else "")
            table.add_row(g.scope, server, _geo_cell(g.cc, g.region), g.services, str(len(g.clients)), str(g.conns),
                          fmt_rate(g.rate_up), fmt_rate(g.rate_down), fmt_bytes(g.total))
            group_focus = focus if focus.level >= LEVEL_SERVER else focus.into_group(g)
            self._table_targets.append(group_focus)
            for c in g.clients:
                client = c.label + (f" ({c.ip})" if c.name else "")
                geo = _geo_cell(c.cc, c.region) if c.remote == c.ip else ""
                table.add_row("", f"  └ {client}", geo, "", "", str(c.conns),
                              fmt_rate(c.rate_up), fmt_rate(c.rate_down), fmt_bytes(c.total))
                self._table_targets.append(group_focus.into_client(c))
        if table.row_count:
            table.move_cursor(row=min(row, table.row_count - 1))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "conns":
            if 0 <= event.cursor_row < len(self._conn_targets):
                self.view = "map"
                self.set_focus_path(self._conn_targets[event.cursor_row])
            return
        if 0 <= event.cursor_row < len(self._table_targets):
            target = self._table_targets[event.cursor_row]
            if target != self.focus_path:
                self.set_focus_path(target)

    # -- zoom & selection --------------------------------------------------
    def set_focus_path(self, focus: Focus, selected: tuple | None = None) -> None:
        self.focus_path = focus
        self.selected = selected
        self.hints = False
        self._hint_buffer = ""
        self.update_watch()
        self.update_view()

    def select(self, key: tuple | None) -> None:
        self.selected = key
        self.update_view()

    def zoom_into(self, hit) -> None:
        if hit.pane is not None:
            self.set_focus_path(Focus(scope=hit.pane))
        elif hit.client is not None:
            self.set_focus_path(self.focus_path.into_client(hit.client))
        elif hit.group is not None and not hit.others:
            self.set_focus_path(self.focus_path.into_group(hit.group))

    def action_zoom_in(self) -> None:
        painter = self.query_one(TreemapView).painter
        hit = next((h for h in painter.selectables() if h.key == self.selected), None) if painter else None
        if hit is not None:
            self.zoom_into(hit)

    def action_zoom_out(self) -> None:
        f = self.focus_path
        if f.level == LEVEL_ALL:
            return
        # keep the box we came from selected, so Enter goes straight back in
        if f.client is not None:
            back_to = ("c", f.client)
        elif f.server is not None:
            back_to = ("g", f.scope, f.server, f.service)
        else:
            back_to = ("p", f.scope)
        self.set_focus_path(f.up(), back_to)

    def action_move(self, direction: str) -> None:
        painter = self.query_one(TreemapView).painter
        if painter is None or self.view != "map" or self.focus_path.level == LEVEL_CLIENT:
            return
        items = painter.selectables()
        keys = [h.key for h in items]
        current = keys.index(self.selected) if self.selected in keys else None
        i = nearest([h.rect for h in items], current, direction)
        if i is not None:
            self.select(keys[i])

    def action_toggle_hints(self) -> None:
        if self.view != "map" or self.focus_path.level == LEVEL_CLIENT:
            return
        self.hints = not self.hints
        self._hint_buffer = ""
        self.update_view()

    def hint_key(self, letter: str) -> None:
        painter = self.query_one(TreemapView).painter
        targets = painter.hint_map() if painter else {}
        self._hint_buffer += letter
        if self._hint_buffer in targets:
            self.zoom_into(targets[self._hint_buffer])
        elif not any(label.startswith(self._hint_buffer) for label in targets):
            self._hint_buffer = ""  # no such label: start over
            self.update_view()
        else:
            self.update_view()

    def action_escape(self) -> None:
        if self.query_one("#filter", Input).display:
            self._close_filter()
        elif self.view == "stream":
            self.action_view("conns")
        elif self.hints:
            self.hints = False
            self._hint_buffer = ""
            self.update_view()
        elif self.focus_path.level > LEVEL_ALL:
            self.action_zoom_out()
        elif self.filter_text:
            self.apply_filter("")

    def update_status(self, shown: int | None = None) -> None:
        parts = [self.source.description]
        if self.source.error:
            parts.append(f"[red]{self.source.error}[/]")
        elif self.source.finished:
            parts.append("[yellow]input ended[/]")
        if self.paused:
            parts.append("[b yellow]PAUSED[/]")
        if self.source.payload_bytes:
            parts.append(f"[b red]payload {self.source.payload_bytes}B[/]")
        if self.view != "map":
            parts.append(f"view:{self.view}")
        arrow = "↑" if self.sort_reverse else "↓"
        geo_status = self.geo.status() if self.geo else None
        if geo_status:
            color = "red" if geo_status[0] == "error" else "yellow"
            parts.append(f"[{color}]{geo_status[1]}[/]")
        parts += [
            f"size:{self.metric}/{self.scale}",
            f"color:{self.color}",
            f"sort:{self.sort_key}{arrow}",
            f"group:{self.group_mode}",
            f"pkts:{self.model.packets} Σ{fmt_bytes(self.model.bytes)}",
        ]
        if self.filter_error:
            parts.append(f"[red]filter error: {self.filter_error}[/]")
        elif self.filter_text:
            n = f" ({shown}/{len(self.pairs)} pairs)" if shown is not None else ""
            parts.append(f"[cyan]filter: {self.filter_text}{n}[/]")
        self.query_one("#status", Static).update(" │ ".join(parts))

    def check_geo_update(self) -> None:
        """Announce once when a background GeoIP download finishes or fails."""
        state = self.geo.state if self.geo else None
        if state == self._geo_state:
            return
        if state == "updated":
            self.notify("GeoIP database updated", timeout=5)
        elif state == "update-failed":
            self.notify(self.geo.error or "GeoIP download failed", severity="error", timeout=10)
        self._geo_state = state

    def hover(self, text: str) -> None:
        self.query_one("#hover", Static).update(text)

    # -- actions ---------------------------------------------------------
    def action_cycle_sort(self) -> None:
        self.sort_key = SORT_KEYS[(SORT_KEYS.index(self.sort_key) + 1) % len(SORT_KEYS)]
        self.update_view()

    def action_reverse(self) -> None:
        self.sort_reverse = not self.sort_reverse
        self.update_view()

    def action_cycle_metric(self) -> None:
        self.metric = METRIC_TOTAL if self.metric == METRIC_RATE else METRIC_RATE
        self.update_view()

    def action_cycle_scale(self) -> None:
        self.scale = SCALES[(SCALES.index(self.scale) + 1) % len(SCALES)]
        self.update_view()

    def action_cycle_color(self) -> None:
        self.color = COLOR_MODES[(COLOR_MODES.index(self.color) + 1) % len(COLOR_MODES)]
        self.update_view()

    def action_toggle_group(self) -> None:
        self.group_mode = GROUP_SERVICE if self.group_mode == GROUP_HOST else GROUP_HOST
        self.update_view()

    def action_cycle_panes(self) -> None:
        scope = self.focus_path.scope
        self.set_focus_path(Focus(scope=PANE_CYCLE[(PANE_CYCLE.index(scope) + 1) % len(PANE_CYCLE)]))

    def action_toggle_table(self) -> None:
        self.action_view("map" if self.view == "table" else "table")

    def action_view(self, view: str) -> None:
        if view == "stream" and self.follower.target is None:
            self.action_follow()  # nothing followed yet: pick the busiest connection in focus
            return
        if self.view == "stream" and view != "stream":
            self.follower.stop()  # payload of the followed connection is only kept while watching it
            self._reset_stream_log()
        was_dump = self.view == "dump"
        self.view = view
        self.hints = False
        self.update_panels()
        if (view == "dump") != was_dump:
            self.update_watch()
        widget = {"table": "#table", "conns": "#conns", "dump": "#dump", "stream": "#stream"}.get(view)
        (self.query_one(widget) if widget else self.query_one(TreemapView)).focus()
        self.update_view()

    def action_toggle_payload(self) -> None:
        if self.source.payload_bytes:
            self.source.payload_bytes = 0
            self.notify("Payload capture off", timeout=3)
        else:
            self.source.payload_bytes = PAYLOAD_BYTES
            self.notify(f"Payload capture on: the first {PAYLOAD_BYTES} bytes of each packet in focus are "
                        "kept in memory and shown in the dump (3)", severity="warning", timeout=6)
        self.update_status()

    def action_pause(self) -> None:
        self.paused = not self.paused
        self.update_status()

    def action_reset(self) -> None:
        self.model.reset_totals()
        self.tick()

    def action_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        inp.display = True
        inp.value = self.filter_text
        inp.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._close_filter()
        self.apply_filter(event.value)

    def _close_filter(self) -> None:
        self.query_one("#filter", Input).display = False
        widget = {"table": "#table", "conns": "#conns", "dump": "#dump", "stream": "#stream"}.get(self.view)
        (self.query_one(widget) if widget else self.query_one(TreemapView)).focus()

    def apply_filter(self, text: str) -> None:
        try:
            self.filter_pred = parse_filter(text)
            self.filter_text = text.strip()
            self.filter_error = ""
        except FilterError as e:
            self.filter_error = str(e)
        self.update_view()

    def on_unmount(self) -> None:
        self.source.stop()
