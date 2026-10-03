import asyncio

from netmon.app import NetMonApp, TreemapView
from netmon.model import TrafficModel
from netmon.resolver import Resolver
from netmon.sources import DemoSource


async def test_demo_app_renders_and_handles_keys():
    app = NetMonApp(DemoSource(), TrafficModel(), Resolver(enabled=False), interval=0.2)
    async with app.run_test(size=(160, 45)) as pilot:
        await asyncio.sleep(1.0)
        await pilot.pause()
        text = "\n".join(s.text for s in app.query_one(TreemapView)._strips)
        assert "INTRANET" in text and "INTERNET" in text
        assert "192.168.1." in text
        for key in "smcgrvt":
            await pilot.press(key)
        await pilot.press("t")
        await pilot.press("slash")
        await pilot.press(*"port 445", "enter")
        await pilot.pause()
        assert app.filter_text == "port 445"
        assert {p.port for p in app.pairs if app.filter_pred(p, lambda ip: None)} == {445}
        await pilot.hover(TreemapView, offset=(20, 10))
