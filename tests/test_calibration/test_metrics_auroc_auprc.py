"""CR-014 AC-1, AC-2 — AUROC (rank, tie-corrected) and AUPRC (average precision)."""

from __future__ import annotations

import numpy as np
import pytest

from graqle.calibration.metrics import compute_auprc, compute_auroc


def _reference_auroc(s: np.ndarray, y: np.ndarray) -> float:
    """O(n²) pairwise definition: P(pos > neg) + ½·P(tie)."""
    pos, neg = s[y == 1], s[y == 0]
    diff = pos[:, None] - neg[None, :]
    return float(((diff > 0).sum() + 0.5 * (diff == 0).sum()) / (pos.size * neg.size))


def test_hand_computed_six_rows_with_a_tie() -> None:
    # pos {.9,.8,.3} vs neg {.8,.2,.1}: 3 + 2.5 + 2 = 7.5 of 9 pairs
    s = np.array([0.9, 0.8, 0.8, 0.3, 0.2, 0.1])
    y = np.array([1, 1, 0, 1, 0, 0])
    auc, info = compute_auroc(s, y)
    assert auc == pytest.approx(7.5 / 9, abs=1e-12)
    assert info == {"n_pos": 3, "n_neg": 3, "ties": 1}


def test_matches_reference_on_1000_random_sets() -> None:  # AC-1
    rng = np.random.default_rng(20260927)
    for _ in range(1000):
        n = int(rng.integers(2, 60))
        s = np.round(rng.random(n), int(rng.integers(1, 3)))  # coarse rounding ⇒ many ties
        y = rng.integers(0, 2, n)
        if y.min() == y.max():
            y[0] = 1 - y[0]
        assert compute_auroc(s, y)[0] == pytest.approx(_reference_auroc(s, y), abs=1e-9)


@pytest.mark.parametrize("fn", [compute_auroc, compute_auprc])
def test_rejects_non_binary_labels(fn) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="binary"):
        fn(np.array([0.2, 0.7]), np.array([0, 2]))


@pytest.mark.parametrize("y", [[1, 1, 1], [0, 0, 0]])
def test_auroc_single_class_raises(y) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="both classes"):
        compute_auroc(np.array([0.1, 0.5, 0.9]), np.array(y))


def test_auprc_needs_a_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        compute_auprc(np.array([0.1, 0.9]), np.array([0, 0]))


def test_auprc_random_scores_approximate_prevalence() -> None:  # AC-2
    rng = np.random.default_rng(7)
    y = (rng.random(10_000) < 0.3).astype(int)
    ap, info = compute_auprc(rng.random(10_000), y)
    assert ap == pytest.approx(info["prevalence"], abs=0.02)


def test_auprc_perfect_separation_is_one() -> None:  # AC-2
    s = np.array([0.9, 0.8, 0.7, 0.2, 0.1])
    assert compute_auprc(s, np.array([1, 1, 1, 0, 0]))[0] == pytest.approx(1.0)


def test_auprc_all_tied_equals_prevalence() -> None:
    y = np.array([1, 0, 0, 1, 0])
    assert compute_auprc(np.full(5, 0.5), y)[0] == pytest.approx(0.4)


def test_auroc_is_one_for_perfect_and_zero_for_inverted() -> None:
    s = np.array([0.9, 0.8, 0.2, 0.1])
    assert compute_auroc(s, np.array([1, 1, 0, 0]))[0] == 1.0
    assert compute_auroc(s, np.array([0, 0, 1, 1]))[0] == 0.0
