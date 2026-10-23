"""CR-014 AC-4 — checkpoint-conditioned ECE over ABSOLUTE positions."""

from __future__ import annotations

import numpy as np
import pytest

from graqle.calibration.metrics import compute_ece, tc_ece

RNG = np.random.default_rng(11)
C = RNG.random(300)
Y = (RNG.random(300) < C).astype(int)
T = RNG.integers(0, 40, 300)
EDGES = [5, 15, 30]


def test_per_bucket_ece_equals_compute_ece_on_the_subset() -> None:
    total, buckets = tc_ece(C, Y, T, EDGES)
    bounds = [(0, 5), (5, 15), (15, 30), (30, None)]
    assert [(b["lo"], b["hi"]) for b in buckets] == bounds
    weighted = 0.0
    for b, (lo, hi) in zip(buckets, bounds):
        mask = (T >= lo) if hi is None else ((T >= lo) & (T < hi))
        assert b["n"] == int(mask.sum())
        assert b["ece"] == pytest.approx(compute_ece(C[mask], Y[mask])[0], abs=1e-12)
        weighted += b["n"] / C.size * b["ece"]
    assert total == pytest.approx(weighted, abs=1e-12)


def test_empty_bucket_reports_none() -> None:
    _, buckets = tc_ece(C[:3], Y[:3], np.array([0, 1, 2]), [100])
    assert buckets[1] == {"lo": 100, "hi": None, "n": 0, "ece": None}


@pytest.mark.parametrize(
    "positions",
    [
        np.linspace(0.0, 1.0, 300),  # normalised by trajectory length
        np.full(300, 3.0),  # integral-valued floats are still floats
        np.zeros(300, dtype=bool),
    ],
)
def test_rejects_non_integer_positions(positions: np.ndarray) -> None:
    with pytest.raises(ValueError, match="normalised positions are rejected"):
        tc_ece(C, Y, positions, EDGES)


def test_rejects_negative_positions() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        tc_ece(C, Y, np.r_[-1, T[1:]], EDGES)


def test_rejects_size_mismatch() -> None:
    with pytest.raises(ValueError, match="size mismatch"):
        tc_ece(C, Y, T[:10], EDGES)


@pytest.mark.parametrize("edges", [[0, 5], [5, 5], [10, 5], [-3]])
def test_rejects_bad_edges(edges: list[int]) -> None:
    with pytest.raises(ValueError, match="strictly increasing positive"):
        tc_ece(C, Y, T, edges)
