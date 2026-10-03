import random

from netmon.treemap import Rect, fit, layout


def covered(rects):
    cells = []
    for r in rects:
        cells += [(x, y) for x in range(r.x, r.x + r.w) for y in range(r.y, r.y + r.h)]
    return cells


def test_layout_tiles_rect_exactly():
    rng = random.Random(0)
    for _ in range(200):
        n = rng.randint(1, 30)
        weights = [rng.random() * 100 + 0.1 for _ in range(n)]
        area = Rect(3, 2, rng.randint(1, 120), rng.randint(1, 40))
        rects = layout(weights, area)
        cells = covered(rects)
        assert len(cells) == len(set(cells)) == area.area
        assert all(area.contains(x, y) for x, y in cells)


def test_layout_is_proportional():
    a, b = layout([3, 1], Rect(0, 0, 80, 10))
    assert (a.w, b.w) == (60, 20)


def test_fit_drops_small_and_zero():
    kept, dropped = fit([100, 0, 1, 50], area=100, min_area=10)
    assert kept == [0, 3]
    assert set(dropped) == {1, 2}
    assert fit([0, 0], 100, 10) == ([], [0, 1])


def test_fit_layout_respects_min_size():
    from netmon.treemap import fit_layout

    weights = [100, 50, 20, 5, 4, 3, 2, 1]
    kept, dropped, rects, others = fit_layout(weights, Rect(0, 0, 60, 12), 14, 2)
    assert kept and all(r.w >= 14 and r.h >= 2 for r in rects)
    assert others is not None and set(kept) | set(dropped) == set(range(len(weights)))


def test_fit_layout_falls_back_to_largest():
    from netmon.treemap import fit_layout

    kept, dropped, rects, others = fit_layout([5, 9, 7], Rect(0, 0, 15, 2), 14, 2)
    assert kept == [1] and rects == [Rect(0, 0, 15, 2)] and others is None
    assert sorted(dropped) == [0, 2]
