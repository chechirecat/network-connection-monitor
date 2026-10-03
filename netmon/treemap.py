"""Treemap layout on an integer character grid."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import accumulate
from typing import Callable, Sequence

# Terminal cells are roughly twice as tall as wide; treat one row as this many columns
# when deciding which way to split so boxes come out visually square-ish.
CELL_ASPECT = 2.0


@dataclass(frozen=True, slots=True)
class Rect:
    x: int
    y: int
    w: int
    h: int

    @property
    def area(self) -> int:
        return max(self.w, 0) * max(self.h, 0)

    def inset(self, n: int = 1) -> Rect:
        return Rect(self.x + n, self.y + n, self.w - 2 * n, self.h - 2 * n)

    def contains(self, x: int, y: int) -> bool:
        return self.x <= x < self.x + self.w and self.y <= y < self.y + self.h


EMPTY = Rect(0, 0, 0, 0)


def layout(weights: Sequence[float], rect: Rect) -> list[Rect]:
    """Split ``rect`` into one rectangle per weight, preserving order.

    Uses recursive binary partitioning: the item list is cut where the
    cumulative weight is closest to half, and the rectangle is cut along its
    visually longer side in that proportion. Items that cannot get at least
    one cell receive ``EMPTY``.
    """
    n = len(weights)
    out = [EMPTY] * n
    if n == 0 or rect.w <= 0 or rect.h <= 0:
        return out
    prefix = [0.0, *accumulate(max(w, 0.0) for w in weights)]

    def rec(lo: int, hi: int, r: Rect) -> None:
        if hi - lo == 1:
            out[lo] = r
            return
        total = prefix[hi] - prefix[lo]
        half = prefix[lo] + total / 2
        split = min(range(lo + 1, hi), key=lambda i: abs(prefix[i] - half))
        frac = (prefix[split] - prefix[lo]) / total if total > 0 else (split - lo) / (hi - lo)
        horizontal = r.w >= r.h * CELL_ASPECT  # side by side
        if horizontal and r.w < 2:
            horizontal = False
        if not horizontal and r.h < 2:
            horizontal = r.w >= 2
            if not horizontal:
                out[lo] = r  # single cell: first item wins, the rest stay empty
                return
        if horizontal:
            a = min(max(round(r.w * frac), 1), r.w - 1)
            rec(lo, split, Rect(r.x, r.y, a, r.h))
            rec(split, hi, Rect(r.x + a, r.y, r.w - a, r.h))
        else:
            a = min(max(round(r.h * frac), 1), r.h - 1)
            rec(lo, split, Rect(r.x, r.y, r.w, a))
            rec(split, hi, Rect(r.x, r.y + a, r.w, r.h - a))

    rec(0, n, rect)
    return out


def fit(weights: Sequence[float], area: int, min_area: int) -> tuple[list[int], list[int]]:
    """Choose which items are big enough to draw.

    Returns (kept indices in original order, dropped indices). Items are
    kept largest-first while each still gets ``min_area`` cells, reserving
    room for an aggregate "others" box when something gets dropped.
    Zero-weight items are always dropped.
    """
    order = sorted((i for i, w in enumerate(weights) if w > 0), key=lambda i: -weights[i])
    zero = [i for i, w in enumerate(weights) if w <= 0]
    total = sum(weights[i] for i in order)
    if total <= 0 or area <= 0:
        return [], order + zero
    max_items = max(area // max(min_area, 1), 1)
    kept: list[int] = []
    for i in order:
        if len(kept) >= max_items:
            break
        if weights[i] / total * area < min_area and kept:
            break
        kept.append(i)
    kept_set = set(kept)
    dropped = [i for i in order if i not in kept_set]
    if dropped and len(kept) >= max_items and len(kept) > 1:
        dropped.insert(0, kept.pop())  # make room for the "others" box
    kept.sort()
    return kept, dropped + zero


def fit_layout(
    weights: Sequence[float],
    rect: Rect,
    min_w: int,
    min_h: int,
    merge: Callable[[list[int]], float] | None = None,
) -> tuple[list[int], list[int], list[Rect], Rect | None]:
    """Lay out as many items as possible so that each is at least ``min_w`` x ``min_h``.

    Returns (kept indices, dropped indices, rects for kept, rect for the
    aggregate "others" box or None). The smallest item is dropped until every
    kept box is big enough. ``merge`` gives the weight of the "others" box for
    the dropped indices (default: sum of their weights). If not even one item
    fits next to the "others" box, the largest item gets the whole rect and
    no "others" box is returned.
    """
    merge = merge or (lambda idx: sum(weights[i] for i in idx))
    kept, dropped = fit(weights, rect.area, min_w * min_h)
    while True:
        live = [i for i in dropped if weights[i] > 0]
        other_w = merge(live) if live else 0.0
        ws = [weights[i] for i in kept] + ([other_w] if other_w > 0 else [])
        rects = layout(ws, rect)
        too_small = any(r.w < min_w or r.h < min_h for r in rects[: len(kept)])
        if not kept and live:
            largest = max(live, key=lambda i: weights[i])
            return [largest], [i for i in dropped if i != largest], [rect], None
        if not too_small or not kept or (len(kept) == 1 and other_w <= 0):
            others = rects[len(kept)] if other_w > 0 else None
            return kept, dropped, rects[: len(kept)], others
        victim = min(kept, key=lambda i: weights[i])
        kept.remove(victim)
        dropped.insert(0, victim)
