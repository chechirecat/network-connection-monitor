"""Textual UI."""

from __future__ import annotations

import time

from rich.markup import escape
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.css.query import NoMatches
from textual.strip import Strip
from textual.widget import Widget
from textual.widgets import DataTable, Footer, Input, Static

from .classify import INTERNET, INTRANET
from .detail import detail_markup
from .focus import LEVEL_ALL, LEVEL_CLIENT, LEVEL_SERVER, Focus, nearest
from .filters import FilterError, parse_filter
from .model import PairView, TrafficModel
from .geo import MAX_AGE_DAYS, REGION_LABELS, GeoDB
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
        Binding("t", "toggle_table", "Table"),
        Binding("p", "pause", "Pause"),
        Binding("z", "reset", "Reset Σ"),
        Binding("escape", "escape", "Back", show=False),
        *(Binding(k, f"move('{d}')", show=False) for k, d in ARROWS.items()),
    ]

    def __init__(
        self, source: Source, model: TrafficModel, resolver: Resolver, geo: GeoDB | None = None, interval: float = 1.0
    ) -> None:
        super().__init__()
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
        self.filter_text = ""
        self.filter_pred = None
        self.filter_error = ""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="crumbs")
            yield TreemapView()
            yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
            yield Static(id="detail")
            yield Static(id="hover")
            yield Static(id="status")
        yield Input(placeholder="filter: host/server/client X · net CIDR · port N · proto tcp · min 10k · "
                    "internet/intranet · text · ! negates · or", id="filter")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Scope", "Server", "Geo", "Services", "Clients", "Conns", "↑ /s", "↓ /s", "Σ total")
        self.source.start(self.model.add)
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

    def update_view(self) -> None:
        names = self.resolver.name
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
        if self.query_one(DataTable).display:
            self.fill_table(groups)
        if focus.level == LEVEL_CLIENT:
            self.query_one("#detail", Static).update(detail_markup(pairs, names, time.monotonic()))
        self.update_crumbs(groups)
        self.update_status(len(pairs))

    def update_panels(self) -> None:
        """Show exactly one of map / table / detail."""
        table = self.query_one(DataTable)
        detail = self.query_one("#detail", Static)
        tree = self.query_one(TreemapView)
        detail_mode = self.focus_path.level == LEVEL_CLIENT and not table.display
        detail.display = detail_mode
        tree.display = not table.display and not detail_mode

    def update_crumbs(self, groups) -> None:
        f = self.focus_path
        parts = ["All"]
        if f.scope:
            parts.append(f.scope.capitalize())
        if f.server:
            g = groups[0] if groups else None
            cc = f"{g.cc} " if g and g.server_is_remote and g.cc else ""
            label = g.label if g else (self.resolver.name(f.server) or f.server)
            svc = f" {service_name(*f.service)}" if f.service else ""
            parts.append(f"{cc}{label}{svc}")
        if f.client:
            parts.append(self.resolver.name(f.client) or f.client)
        crumbs = " › ".join(f"[b]{escape(p)}[/]" if i == len(parts) - 1 else escape(p) for i, p in enumerate(parts))
        if self.hints:
            help_text = f"type letters to zoom{' — ' + self._hint_buffer if self._hint_buffer else ''} · Esc cancel"
        elif f.level == LEVEL_CLIENT:
            help_text = "Esc back"
        else:
            help_text = "Space letters · arrows + Enter zoom · double-click zoom" + (" · Esc back" if f.level else "")
        self.query_one("#crumbs", Static).update(f"{crumbs}   [dim]{help_text}[/]")

    def fill_table(self, groups) -> None:
        table = self.query_one(DataTable)
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
        if painter is None or self.focus_path.level == LEVEL_CLIENT:
            return
        items = painter.selectables()
        keys = [h.key for h in items]
        current = keys.index(self.selected) if self.selected in keys else None
        i = nearest([h.rect for h in items], current, direction)
        if i is not None:
            self.select(keys[i])

    def action_toggle_hints(self) -> None:
        if self.focus_path.level == LEVEL_CLIENT or not self.query_one(TreemapView).display:
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
        table = self.query_one(DataTable)
        table.display = not table.display
        self.hints = False
        self.update_panels()
        (table if table.display else self.query_one(TreemapView)).focus()
        self.update_view()

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
        table = self.query_one(DataTable)
        (table if table.display else self.query_one(TreemapView)).focus()

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
