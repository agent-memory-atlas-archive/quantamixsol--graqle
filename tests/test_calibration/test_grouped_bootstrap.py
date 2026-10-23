"""CR-014 AC-5 — grouped bootstrap resamples groups, never rows."""

from __future__ import annotations

import numpy as np
import pytest

from graqle.calibration.metrics import compute_auroc, compute_brier_score, grouped_bootstrap

RNG = np.random.default_rng(3)
S = RNG.random(120)
Y = (RNG.random(120) < S).astype(int)
G = np.repeat(np.arange(40), 3)


def _brier(scores: np.ndarray, labels: np.ndarray) -> float:
    return compute_brier_score(scores, labels)


def test_single_group_collapses_ci_to_point() -> None:  # AC-5
    out = grouped_bootstrap(_brier, {"scores": S, "labels": Y}, np.zeros(120), 200, 0.1, 42)
    assert out["ci_low"] == out["point"] == out["ci_high"]
    assert out["n_groups"] == 1


def test_resamples_whole_groups() -> None:
    sizes: list[int] = []

    def size(rows: np.ndarray) -> float:
        sizes.append(rows.size)
        return float(rows.size)

    ragged = np.repeat(np.arange(4), [1, 2, 4, 8])
    grouped_bootstrap(size, {"rows": np.arange(15)}, ragged, 100, 0.1, 1)
    # every resample draws 4 whole groups from sizes {1,2,4,8}; row-level
    # resampling would always give exactly 15
    assert len(set(sizes[:-1])) > 1


def test_deterministic_for_a_seed() -> None:
    a = grouped_bootstrap(_brier, {"scores": S, "labels": Y}, G, 150, 0.1, 9)
    b = grouped_bootstrap(_brier, {"scores": S, "labels": Y}, G, 150, 0.1, 9)
    assert a == b and a["seed"] == 9


def test_invalid_resamples_are_dropped_and_counted() -> None:
    y = np.r_[np.ones(3, int), np.zeros(117, int)]  # positives only in group 0
    out = grouped_bootstrap(
        lambda scores, labels: compute_auroc(scores, labels)[0],
        {"scores": S, "labels": y},
        G,
        200,
        0.1,
        5,
    )
    assert out["n_dropped"] > 0
    assert out["n_valid"] + out["n_dropped"] == 200


def test_all_invalid_raises() -> None:
    with pytest.raises(ValueError, match="every resample"):
        grouped_bootstrap(
            lambda scores, labels: compute_auroc(scores, labels)[0],
            {"scores": S[:3], "labels": np.ones(3, int)},
            np.zeros(3),
            20,
            0.1,
            1,
        )


@pytest.mark.parametrize(("n", "alpha"), [(0, 0.1), (10, 0.0), (10, 1.0)])
def test_rejects_bad_parameters(n: int, alpha: float) -> None:
    with pytest.raises(ValueError):
        grouped_bootstrap(_brier, {"scores": S, "labels": Y}, G, n, alpha, 1)


def test_rejects_misaligned_groups() -> None:
    with pytest.raises(ValueError, match="one row per group"):
        grouped_bootstrap(_brier, {"scores": S, "labels": Y}, G[:10], 10, 0.1, 1)
