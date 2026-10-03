# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
.venv/bin/pip install -e '.[dev]'      # install (venv already exists; system python has no pip/ensurepip)
.venv/bin/pytest -q                    # all tests
.venv/bin/pytest tests/test_treemap.py::test_layout_tiles_rect_exactly
.venv/bin/netmon --demo                # run the UI with synthetic traffic (no root)
```

No linter/formatter is configured. Tests use `pytest-asyncio` in auto mode (plain `async def test_…`); `tests/helpers.py` builds raw IPv4/IPv6/Ethernet packets and pcap blobs for parser/source tests.

Live capture needs root, which is not available in agent sessions; verify UI changes with `--demo`, a pcap file, or headless `App.run_test()` (see `tests/test_app.py`).

## Architecture

Data flows one way: **source thread → `TrafficModel` → per-tick snapshot → grouping/filter/sort → painter → Textual widget**.

- `sources.py` — `LiveSource` (AF_PACKET `SOCK_DGRAM`, so no link-layer parsing; loopback duplicates dropped), `PcapSource` (classic pcap, file or stdin), `DemoSource`. Each runs in a daemon thread and calls `model.add(Packet)`.
- `packets.py` — the only parser: `parse_ip` (used by live capture) and `parse_frame` (pcap link types: Ethernet/VLAN, raw, Linux SLL/SLL2, null) both produce a `Packet`.
- `model.py` — thread-safe accounting keyed by **pair** = (client ip, server ip, server port, proto). Client/server role is decided once per 5-tuple flow: TCP SYN wins, otherwise the port heuristic in `classify.dst_is_server`. `tick()` (called by the UI timer) computes EMA rates, expires idle pairs/flows, and returns immutable `PairView`s. Intranet/internet scope is fixed per pair at creation (`classify.Classifier`, own CIDR list — intentionally not `ipaddress.is_private`).
- `geo.py` — offline IP→country (`GeoDB`: sorted uint64 range arrays + bisect; IPv6 reduced to /64) and country→distance region. `GeoDB.start()` loads in a background thread and, for the default cache path only, re-downloads when the file is missing or older than `MAX_AGE_DAYS`; `state`/`status()` drive the status bar and the startup/finished toasts in `app.py`. Tables are swapped atomically on reload. `lookup` returns None until ready. `TrafficModel` stores each pair's `remote` (non-local endpoint) and resolves `remote_cc` on every `tick()`, so countries appear once loading finishes. `--demo` without a DB uses `DemoSource.GEO_ROWS`.
- `views.py` — aggregates `PairView`s into `GroupView` (server box) → `ClientView` (inner box). Group mode `host` merges all ports of a server; `service` splits by port+proto. Filtering (`filters.py`) operates on pairs *before* grouping.
- `treemap.py` — integer-grid binary-partition layout (order-preserving, tiles the rect exactly). `fit_layout()` drops the smallest items until every box meets a minimum width/height; dropped items become a "+N more" box sized by `merge` (the painter sizes it as if it were one item carrying all leftover traffic).
- `render.py` — `Painter` lays out on *scaled* weights (`sqrt`/`log`/`linear`, see `Painter.scaled`) and draws panes onto a `Canvas` (char + Rich `Style` grid → Textual `Strip`s) and records `Hit` regions for mouse hover.
- `focus.py` — zoom state `Focus(scope, server, service, client)`; its `level` (all/pane/server/client) drives everything: pairs are filtered with `Focus.matches` before the user filter, the painter draws one full-screen server box at level ≥ server, and level client swaps the map for the `detail.py` text view. `nearest()` does arrow-key navigation over hit rects.
- Selection and letter hints work on `Painter.selectables()` (pane title hits at level all, server boxes at all/pane, client boxes at server level); `Hit.key` is the identity used for `selected` (`("p", scope)`, `("g", scope, server, service)`, `("c", ip)`). Selection highlights are drawn inside `draw_group`/`draw_client` so text is never covered; hint letters go on box corners.
- `app.py` — `TreemapView` caches strips and repaints only on new data or resize; `NetMonApp` holds all view state (focus, selection, hints, sort, metric, color, group mode, filter) and rebuilds the view from the last snapshot on every key press.

Gotchas: Textual reads keys from fd 0, so `--pcap -` dups stdin for the capture and `dup2`s `/dev/tty` onto fd 0 (`__main__.py`). Don't name widget attributes `_size`/`_dirty` etc. — they clash with Textual internals.
