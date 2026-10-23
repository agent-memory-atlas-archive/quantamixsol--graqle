"""Calibration metrics for GraQle confidence scoring (R11 .

Numpy-only implementations of standard calibration metrics:
- Expected Calibration Error (ECE)
- Maximum Calibration Error (MCE)
- Brier Score

No scipy or sklearn dependencies.
"""

# ── graqle:intelligence ──
# module: graqle.calibration.metrics
# risk: LOW (impact radius: 3 modules)
# consumers: calibration_pipeline, benchmark_runner
# dependencies: __future__, numpy
# constraints: numpy-only — no scipy, no sklearn
# ── /graqle:intelligence ──

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import numpy as np


def _validate_inputs(
    confidences: np.ndarray,
    correctness: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Validate and normalize calibration inputs.

    Raises ValueError on empty input, size mismatch, or out-of-range values.
    """
    confidences = np.asarray(confidences, dtype=np.float64).ravel()
    correctness = np.asarray(correctness, dtype=np.float64).ravel()

    if confidences.size == 0:
        raise ValueError("confidences array is empty")
    if confidences.size != correctness.size:
        raise ValueError(
            f"Shape mismatch: confidences={confidences.size}, "
            f"correctness={correctness.size}"
        )
    if np.any((confidences < 0.0) | (confidences > 1.0)):
        raise ValueError(
            "confidences must be in [0, 1]; "
            f"got range [{confidences.min():.4f}, {confidences.max():.4f}]"
        )
    return confidences, correctness


def compute_ece(
    confidences: np.ndarray,
    correctness: np.ndarray,
    n_bins: int = 10,
) -> tuple[float, dict]:
    """Compute Expected Calibration Error with reliability diagram data.

    Uses equal-width bins over [0, 1].

    Parameters
    ----------
    confidences : np.ndarray
        Predicted confidence scores in [0, 1].
    correctness : np.ndarray
        Binary correctness labels (1 = correct, 0 = incorrect).
    n_bins : int
        Number of equal-width bins (default 10).

    Returns
    -------
    tuple[float, dict]
        ``(ece_value, reliability_diagram)`` where *reliability_diagram*
        maps ``bin_center -> (accuracy, mean_confidence, count)``.
    """
    confidences, correctness = _validate_inputs(confidences, correctness)

    if n_bins < 1:
        raise ValueError(f"n_bins must be >= 1, got {n_bins}")

    n_samples = confidences.size
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    reliability: dict[float, tuple[float, float, int]] = {}
    ece = 0.0

    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        bin_center = round((lo + hi) / 2.0, 4)

        # Last bin is inclusive on the right edge to capture confidence == 1.0
        if i < n_bins - 1:
            mask = (confidences >= lo) & (confidences < hi)
        else:
            mask = (confidences >= lo) & (confidences <= hi)

        count = int(mask.sum())
        if count == 0:
            continue

        bin_acc = float(correctness[mask].mean())
        bin_conf = float(confidences[mask].mean())
        reliability[bin_center] = (bin_acc, bin_conf, count)
        ece += (count / n_samples) * abs(bin_acc - bin_conf)

    return float(ece), reliability


def compute_mce(
    confidences: np.ndarray,
    correctness: np.ndarray,
    n_bins: int = 10,
) -> float:
    """Compute Maximum Calibration Error — worst-case bin gap.

    Parameters
    ----------
    confidences : np.ndarray
        Predicted confidence scores in [0, 1].
    correctness : np.ndarray
        Binary correctness labels (1 = correct, 0 = incorrect).
    n_bins : int
        Number of equal-width bins (default 10).

    Returns
    -------
    float
        Maximum |accuracy - confidence| across all non-empty bins.
    """
    _, reliability = compute_ece(confidences, correctness, n_bins=n_bins)

    if not reliability:
        return 0.0

    return float(max(abs(acc - conf) for acc, conf, _ in reliability.values()))


def compute_brier_score(
    confidences: np.ndarray,
    correctness: np.ndarray,
) -> float:
    """Compute Brier Score — mean squared error between confidence and correctness.

    Parameters
    ----------
    confidences : np.ndarray
        Predicted confidence scores in [0, 1].
    correctness : np.ndarray
        Binary correctness labels (1 = correct, 0 = incorrect).

    Returns
    -------
    float
        Mean squared difference. Lower is better; 0.0 for empty input.
    """
    confidences, correctness = _validate_inputs(confidences, correctness)

    return float(np.mean((confidences - correctness) ** 2))


# ---------------------------------------------------------------------------
# DAG-2026 CR-014 PR-014a — discrimination, selective-prediction and
# position-conditioned calibration metrics, plus a grouped bootstrap.
# numpy-only (module constraint). The functions above are unchanged.
# ---------------------------------------------------------------------------


def _binary_labels(labels: np.ndarray) -> np.ndarray:
    """Reject anything but 0/1 labels (a ranking metric on other labels is meaningless)."""
    if not np.all((labels == 0.0) | (labels == 1.0)):
        raise ValueError("labels must be binary (0 or 1)")
    return labels


def _average_ranks(values: np.ndarray) -> np.ndarray:
    """1-based ranks with ties sharing their average rank (Mann-Whitney convention)."""
    order = np.argsort(values, kind="mergesort")
    sorted_values = values[order]
    _, first_index, counts = np.unique(sorted_values, return_index=True, return_counts=True)
    average = first_index + (counts + 1) / 2.0
    ranks = np.empty(values.size, dtype=np.float64)
    ranks[order] = np.repeat(average, counts)
    return ranks


def _trapezoid(y: np.ndarray, x: np.ndarray) -> float:
    """Trapezoid rule, independent of the numpy trapz/trapezoid rename."""
    if y.size < 2:
        return 0.0
    return float(np.sum((x[1:] - x[:-1]) * (y[1:] + y[:-1]) / 2.0))


def compute_auroc(scores: np.ndarray, labels: np.ndarray) -> tuple[float, dict]:
    """Area under the ROC curve: P(score_pos > score_neg) + half of P(tie).

    Rank-based (Mann-Whitney U with tie correction), O(n log n). Raises
    ``ValueError`` when either class is absent: it never returns 0.5 silently.
    """
    s, y = _validate_inputs(scores, labels)
    y = _binary_labels(y)
    n_pos = int(y.sum())
    n_neg = int(y.size - n_pos)
    if n_pos == 0 or n_neg == 0:
        raise ValueError("compute_auroc requires both classes present")
    ranks = _average_ranks(s)
    u = ranks[y == 1.0].sum() - n_pos * (n_pos + 1) / 2.0
    ties = int(s.size - np.unique(s).size)
    return float(u / (n_pos * n_neg)), {"n_pos": n_pos, "n_neg": n_neg, "ties": ties}


def compute_auprc(scores: np.ndarray, labels: np.ndarray) -> tuple[float, dict]:
    """Average precision (area under the precision-recall curve), step interpolation.

    Tied scores are one threshold: precision and recall are read only at the
    last row of each tie group. The no-skill baseline is the prevalence,
    returned in the info dict.
    """
    s, y = _validate_inputs(scores, labels)
    y = _binary_labels(y)
    n_pos = float(y.sum())
    if n_pos == 0:
        raise ValueError("compute_auprc requires at least one positive")
    order = np.argsort(-s, kind="stable")
    s_sorted, y_sorted = s[order], y[order]
    tp = np.cumsum(y_sorted)
    fp = np.cumsum(1.0 - y_sorted)
    precision = tp / (tp + fp)
    recall = tp / n_pos
    boundaries = np.r_[np.where(np.diff(s_sorted) != 0)[0], s.size - 1]
    p, r = precision[boundaries], recall[boundaries]
    ap = float(np.sum((r - np.r_[0.0, r[:-1]]) * p))
    return ap, {"prevalence": float(y.mean()), "n": int(s.size)}


@dataclass(frozen=True)
class RiskCoverage:
    """Selective-prediction curve: risk at each coverage level, plus AURC and E-AURC."""

    coverage: np.ndarray = field(repr=False)
    risk: np.ndarray = field(repr=False)
    aurc: float
    e_aurc: float
    n: int

    def summary(self) -> dict:
        return {"aurc": self.aurc, "e_aurc": self.e_aurc, "n": self.n}


def risk_coverage_curve(scores: np.ndarray, labels: np.ndarray) -> RiskCoverage:
    """Risk-coverage curve for selective prediction (label 1 = correct).

    Rows are accepted in descending score order; ``risk[k]`` is the error rate
    among the first ``k + 1`` accepted rows. ``e_aurc = aurc - aurc_oracle``,
    where the oracle accepts every correct row first, so ``e_aurc >= 0``.
    """
    s, y = _validate_inputs(scores, labels)
    y = _binary_labels(y)
    order = np.argsort(-s, kind="stable")
    err = 1.0 - y[order]
    k = np.arange(1, s.size + 1, dtype=np.float64)
    coverage = k / s.size
    risk = np.cumsum(err) / k
    risk_oracle = np.cumsum(np.sort(err)) / k
    aurc = _trapezoid(risk, coverage)
    e_aurc = max(0.0, aurc - _trapezoid(risk_oracle, coverage))
    return RiskCoverage(coverage=coverage, risk=risk, aurc=aurc, e_aurc=e_aurc, n=int(s.size))


def tc_ece(
    confidences: np.ndarray,
    labels: np.ndarray,
    positions: Sequence[int] | np.ndarray,
    position_edges: Sequence[int],
    n_bins: int = 10,
) -> tuple[float, list[dict]]:
    """Checkpoint-conditioned ECE: ECE per bucket of ABSOLUTE checkpoint index.

    ``positions`` must be integer checkpoint indices. Positions normalised by
    the final trajectory length are rejected, because that length is only
    known after the outcome. Buckets are ``[0, e_1), [e_1, e_2), ..., [e_K, inf)``
    for the strictly increasing positive ``position_edges``. Each bucket's ECE
    is :func:`compute_ece` on that bucket; the total weights buckets by size.
    """
    c, y = _validate_inputs(confidences, labels)
    t = np.asarray(positions).ravel()
    if not np.issubdtype(t.dtype, np.integer):
        raise ValueError(
            "positions must be integer checkpoint indices; normalised positions are rejected"
        )
    if t.size != c.size:
        raise ValueError(f"positions size mismatch: {t.size} vs {c.size}")
    if np.any(t < 0):
        raise ValueError("positions must be absolute non-negative checkpoint indices")
    edges = [int(e) for e in position_edges]
    if any(e <= 0 for e in edges) or any(b <= a for a, b in zip(edges, edges[1:])):
        raise ValueError("position_edges must be strictly increasing positive integers")

    bounds: list[tuple[int, int | None]] = list(zip([0, *edges], [*edges, None]))
    total = 0.0
    buckets: list[dict] = []
    for lo, hi in bounds:
        mask = (t >= lo) if hi is None else ((t >= lo) & (t < hi))
        n_k = int(mask.sum())
        if n_k == 0:
            buckets.append({"lo": lo, "hi": hi, "n": 0, "ece": None})
            continue
        ece_k, reliability = compute_ece(c[mask], y[mask], n_bins=n_bins)
        buckets.append({"lo": lo, "hi": hi, "n": n_k, "ece": ece_k, "reliability": reliability})
        total += (n_k / c.size) * ece_k
    return float(total), buckets


def grouped_bootstrap(
    metric_fn: Callable[..., float],
    arrays: dict[str, np.ndarray],
    groups: np.ndarray,
    n_resamples: int,
    alpha: float,
    seed: int,
) -> dict:
    """Percentile CI from a cluster bootstrap: resample GROUPS, never rows.

    ``metric_fn(**arrays)`` must return a float. A resample on which the metric
    raises ``ValueError`` (for example a single-class draw for AUROC) is
    dropped and counted in ``n_dropped``; if every resample is dropped the call
    raises instead of reporting a CI.
    """
    if n_resamples < 1:
        raise ValueError("n_resamples must be >= 1")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    g = np.asarray(groups).ravel()
    columns = {k: np.asarray(v) for k, v in arrays.items()}
    if any(v.shape[0] != g.size for v in columns.values()):
        raise ValueError("every array must have one row per group label")

    rng = np.random.default_rng(seed)
    unique_groups = np.unique(g)
    rows_by_group = [np.flatnonzero(g == u) for u in unique_groups]
    values: list[float] = []
    for _ in range(n_resamples):
        chosen = rng.integers(0, unique_groups.size, size=unique_groups.size)
        idx = np.concatenate([rows_by_group[i] for i in chosen])
        try:
            values.append(float(metric_fn(**{k: v[idx] for k, v in columns.items()})))
        except ValueError:
            continue
    if not values:
        raise ValueError("grouped_bootstrap: every resample was invalid for this metric")
    draws = np.asarray(values)
    return {
        "point": float(metric_fn(**columns)),
        "ci_low": float(np.percentile(draws, 100.0 * alpha / 2.0)),
        "ci_high": float(np.percentile(draws, 100.0 * (1.0 - alpha / 2.0))),
        "n_valid": int(draws.size),
        "n_dropped": int(n_resamples - draws.size),
        "seed": int(seed),
        "n_groups": int(unique_groups.size),
    }
