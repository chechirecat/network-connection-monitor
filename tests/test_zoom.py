import asyncio

from netmon.app import NetMonApp, TreemapView
from netmon.focus import LEVEL_ALL, LEVEL_CLIENT, LEVEL_PANE, LEVEL_SERVER, Focus, hint_labels, nearest
from netmon.model import PairView, TrafficModel
from netmon.packets import TCP
from netmon.resolver import Resolver
from netmon.sources import DemoSource
from netmon.treemap import Rect


def test_hint_labels():
    assert hint_labels(3) == ["A", "B", "C"]
    labels = hint_labels(30)
    assert len(set(labels)) == 30 and all(len(x) == 2 for x in labels)


def test_nearest():
    #  [0][1]
    #  [2   ]
    rects = [Rect(0, 0, 10, 5), Rect(10, 0, 10, 5), Rect(0, 5, 20, 5)]
    assert nearest(rects, 0, "right") == 1
    assert nearest(rects, 1, "left") == 0
    assert nearest(rects, 1, "down") == 2
    assert nearest(rects, 2, "up") in (0, 1)
    assert nearest(rects, 0, "left") == 0  # nothing there: stay
    assert nearest(rects, None, "down") == 0


def test_focus_matching_and_up():
    p = PairView("192.168.1.2", "1.2.3.4", 443, TCP, "internet", 1, frozenset(), 0, 0, 1, 0, 0, 0)
    f = Focus(scope="internet", server="1.2.3.4", service=(443, TCP), client="192.168.1.2")
    assert f.level == LEVEL_CLIENT and f.matches(p)
    assert not Focus(scope="intranet").matches(p)
    assert not Focus(scope="internet", server="1.2.3.4", service=(80, TCP)).matches(p)
    assert f.up().level == LEVEL_SERVER and f.up().up().level == LEVEL_PANE and f.up().up().up() == Focus()


async def _app(pilot_size=(160, 45)):
    app = NetMonApp(DemoSource(), TrafficModel(), Resolver(enabled=False), interval=0.2)
    return app


def _screen(app):
    return "\n".join(s.text for s in app.query_one(TreemapView)._strips)


async def test_zoom_with_letters_arrows_and_escape():
    app = await _app()
    async with app.run_test(size=(160, 45)) as pilot:
        await asyncio.sleep(1.0)
        await pilot.pause()

        # letters: at the overview, A and B are the pane titles
        await pilot.press("space")
        await pilot.pause()
        assert app.hints
        await pilot.press("b")
        await pilot.pause()
        assert app.focus_path == Focus(scope="internet") and not app.hints
        assert "INTRANET" not in _screen(app)

        # letters again: A is the biggest internet server
        await pilot.press("space", "a")
        await pilot.pause()
        assert app.focus_path.level == LEVEL_SERVER and app.focus_path.scope == "internet"
        server = app.focus_path.server
        assert server in _screen(app) or app.resolver.name(server)

        # arrows + Enter: select a client and open the detail view
        await pilot.press("right", "enter")
        await pilot.pause()
        assert app.focus_path.level == LEVEL_CLIENT
        detail = str(app.query_one("#detail").render())
        assert server in detail and "service" in detail
        assert "›" in str(app.query_one("#crumbs").render())

        # shortcut letters still work when hints are off
        await pilot.press("s")
        assert app.sort_key == "name"

        # Esc walks back up, keeping the box we came from selected
        await pilot.press("escape")
        await pilot.pause()
        assert app.focus_path.level == LEVEL_SERVER and app.selected[0] == "c"
        await pilot.press("escape")
        await pilot.pause()
        assert app.focus_path.level == LEVEL_PANE and app.selected == ("g", "internet", server, None)
        await pilot.press("escape", "escape")
        await pilot.pause()
        assert app.focus_path.level == LEVEL_ALL


async def test_double_click_and_table_drilldown():
    app = await _app()
    async with app.run_test(size=(160, 45)) as pilot:
        await asyncio.sleep(1.0)
        await pilot.pause()
        tv = app.query_one(TreemapView)
        hit = next(h for h in tv.painter.selectables() if h.group is not None)
        await pilot.double_click(TreemapView, offset=(hit.rect.x + 2, hit.rect.y + 2))
        await pilot.pause()
        assert app.focus_path.level == LEVEL_SERVER and app.focus_path.server == hit.group.server

        await pilot.press("backspace", "backspace", "t")
        await pilot.pause()
        assert app.focus_path.level == LEVEL_ALL
        await pilot.press("enter")  # first row = biggest server
        await pilot.pause()
        assert app.focus_path.level == LEVEL_SERVER
        await pilot.press("down", "enter")  # its first client
        await pilot.pause()
        assert app.focus_path.level == LEVEL_CLIENT
