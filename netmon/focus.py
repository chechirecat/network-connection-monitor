"""Zoom state (All › pane › server › client) and keyboard navigation helpers."""

from __future__ import annotations

import string
from dataclasses import dataclass, replace
from itertools import product

from .model import PairView
from .treemap import Rect
from .views import ClientView, GroupView

LEVEL_ALL, LEVEL_PANE, LEVEL_SERVER, LEVEL_CLIENT = range(4)

# what a box on screen stands for; used for selection and letter hints
GroupKey = tuple  # ("g", scope, server, service)
ClientKey = tuple  # ("c", client)


def group_key(g: GroupView) -> GroupKey:
    return ("g", g.scope, g.server, g.service)


def client_key(c: ClientView) -> ClientKey:
    return ("c", c.ip)


@dataclass(frozen=True)
class Focus:
    scope: str | None = None
    server: str | None = None
    service: tuple[int | None, int] | None = None  # set when zoomed in while grouping by service
    client: str | None = None

    @property
    def level(self) -> int:
        if self.client is not None:
            return LEVEL_CLIENT
        if self.server is not None:
            return LEVEL_SERVER
        if self.scope is not None:
            return LEVEL_PANE
        return LEVEL_ALL

    def matches(self, p: PairView) -> bool:
        if self.scope is not None and p.scope != self.scope:
            return False
        if self.server is not None and p.server != self.server:
            return False
        if self.service is not None and (p.port, p.proto) != self.service:
            return False
        return self.client is None or p.client == self.client

    def into_group(self, g: GroupView) -> Focus:
        return Focus(scope=g.scope, server=g.server, service=g.service)

    def into_client(self, c: ClientView) -> Focus:
        return replace(self, client=c.ip)

    def up(self) -> Focus:
        if self.client is not None:
            return replace(self, client=None)
        if self.server is not None:
            return Focus(scope=self.scope)
        return Focus()


def hint_labels(n: int) -> list[str]:
    """``n`` distinct, equally long labels: A..Z, then AA..ZZ."""
    letters = string.ascii_uppercase
    width = 1 if n <= len(letters) else 2
    return ["".join(t) for t in product(letters, repeat=width)][:n]


def nearest(rects: list[Rect], current: int | None, direction: str) -> int | None:
    """Index of the closest rect in ``direction`` (left/right/up/down) from ``rects[current]``."""
    if not rects:
        return None
    if current is None or not 0 <= current < len(rects):
        return 0
    cur = rects[current]
    cx, cy = cur.x + cur.w / 2, cur.y + cur.h / 2
    best, best_score = None, None
    for i, r in enumerate(rects):
        if i == current:
            continue
        # must lie beyond the current box's edge in that direction
        if direction == "right" and r.x < cur.x + cur.w:
            continue
        if direction == "left" and r.x + r.w > cur.x:
            continue
        if direction == "down" and r.y < cur.y + cur.h:
            continue
        if direction == "up" and r.y + r.h > cur.y:
            continue
        # distance along the direction plus a penalty for sideways offset;
        # rows count double because terminal cells are tall
        dx = max(r.x - cx, cx - (r.x + r.w), 0)
        dy = max(r.y - cy, cy - (r.y + r.h), 0) * 2
        along, across = (dx, dy) if direction in ("left", "right") else (dy, dx)
        score = along + 2 * across
        if best_score is None or score < best_score:
            best, best_score = i, score
    return current if best is None else best
