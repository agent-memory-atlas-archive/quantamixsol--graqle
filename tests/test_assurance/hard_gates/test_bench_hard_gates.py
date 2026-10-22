"""CR-013 PR-013c: performance budgets of CR-013 AC-20.

Deviation from the spec text: ``pytest-benchmark`` is not a declared dev
dependency, so budgets are asserted with ``time.perf_counter`` (median of
repeated runs for the median budget, a single run for worst-case budgets).
"""

from __future__ import annotations

import statistics
import time

import pytest

import graqle.core.rbac as rbac
from graqle.assurance.hard_gates import (
    ContradictionRef,
    DependencyNodeRef,
    default_registry,
)

from ._builders import make_ctx, make_settings

REGISTRY = default_registry()
RUNS = 200


def _ms(fn) -> float:  # type: ignore[no-untyped-def]
    t0 = time.perf_counter()
    fn()
    return (time.perf_counter() - t0) * 1000.0


def test_evaluate_all_median_within_5ms_with_rbac_mocked() -> None:
    settings, ctx = make_settings(), make_ctx()  # conftest stubs check_approval
    REGISTRY.evaluate_all(ctx, settings)  # warm-up (lazy imports)
    median = statistics.median(
        _ms(lambda: REGISTRY.evaluate_all(ctx, settings)) for _ in range(RUNS)
    )
    assert median <= 5.0


def test_worst_case_with_slow_rbac_is_bounded_by_the_rbac_timeout() -> None:
    timeout_ms = 400
    settings = make_settings(rbac_timeout_ms=timeout_ms)
    ctx = make_ctx()

    def slow_but_in_time(actor_id: str, tier: str) -> tuple[bool, str]:
        time.sleep((timeout_ms - 50) / 1000.0)
        return True, ""

    original = rbac.check_approval
    rbac.check_approval = slow_but_in_time  # type: ignore[assignment]
    try:
        elapsed = _ms(lambda: REGISTRY.evaluate_all(ctx, settings))
    finally:
        rbac.check_approval = original  # type: ignore[assignment]
    assert elapsed <= timeout_ms + 5


def test_hung_rbac_returns_at_the_timeout_and_fails_closed() -> None:
    timeout_ms = 200
    settings = make_settings(rbac_timeout_ms=timeout_ms)
    ctx = make_ctx()

    def hung(actor_id: str, tier: str) -> tuple[bool, str]:
        time.sleep(2.0)
        return True, ""

    original = rbac.check_approval
    rbac.check_approval = hung  # type: ignore[assignment]
    try:
        t0 = time.perf_counter()
        results = REGISTRY.evaluate_all(ctx, settings)
        elapsed = (time.perf_counter() - t0) * 1000.0
    finally:
        rbac.check_approval = original  # type: ignore[assignment]
    hg06 = next(r for r in results if r.rule_id == "HG-06")
    assert not hg06.passed and "DAG-HG06-RBAC_UNAVAILABLE" in hg06.reason_codes
    assert elapsed <= timeout_ms + 100  # AC-6 bound for the timed-out call


def test_each_gate_stays_within_its_gate_timeout() -> None:
    settings, ctx = make_settings(), make_ctx()
    for result in REGISTRY.evaluate_all(ctx, settings):
        assert result.duration_ms <= settings.gate_timeout_ms


def _large_ctx():  # type: ignore[no-untyped-def]
    return make_ctx(
        dependency_nodes=tuple(
            DependencyNodeRef(node_id=f"n{i}", status="ACTIVE", dirty=False, recomputed=True)
            for i in range(10_000)
        ),
        contradictions=tuple(
            ContradictionRef(a_id=f"a{i}", b_id=f"b{i}", source_ids=("s1", "s2"), materiality=0.1)
            for i in range(1_000)
        ),
    )


def test_large_context_hashing_takes_the_fast_path_without_canon_fallback(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """AC-20 hard gate: an algorithmic invariant, not a wall-clock threshold.

    A wall-clock budget on a shared CI runner measures runner load as much as
    the code (DN-416). The speed-up comes from ``inputs_hash`` taking
    ``_fast_canon`` instead of the pure-Python canonicaliser, so the gate
    asserts exactly that for the real 10^4-node / 10^3-contradiction context.
    """
    from graqle.assurance import _hashing
    from graqle.governance.tamper_evidence import canonicalize

    fast_sizes: list[int | None] = []
    fallbacks: list[int] = []  # byte length of each projection the slow canonicaliser handled
    real_fast, real_canon = _hashing._fast_canon, canonicalize.canon

    def spy_fast(projection):  # type: ignore[no-untyped-def]
        data = real_fast(projection)
        fast_sizes.append(None if data is None else len(data))
        return data

    def spy_canon(projection):  # type: ignore[no-untyped-def]
        data = real_canon(projection)
        fallbacks.append(len(data))
        return data

    monkeypatch.setattr(_hashing, "_fast_canon", spy_fast)
    monkeypatch.setattr(canonicalize, "canon", spy_canon)

    settings = make_settings()
    REGISTRY.evaluate_all(make_ctx(), settings)
    baseline_fallbacks = len(fallbacks)  # fallbacks of the small default context
    fast_sizes.clear()
    fallbacks.clear()

    REGISTRY.evaluate_all(_large_ctx(), settings)

    # the large projections (HG-02 dependency nodes / contradictions) were hashed on the fast path
    assert max(s for s in fast_sizes if s is not None) > 100_000
    # fallbacks do not grow with context size and only ever handle small projections
    assert len(fallbacks) == baseline_fallbacks
    assert all(size < 10_000 for size in fallbacks)


def test_large_context_benchmark_advisory(request) -> None:  # type: ignore[no-untyped-def]
    """Advisory trend measurement (pytest-benchmark); asserts no time threshold.

    pytest-benchmark is not a declared dev dependency, so this skips where it is absent.
    """
    pytest.importorskip("pytest_benchmark")
    benchmark = request.getfixturevalue("benchmark")
    settings, ctx = make_settings(), _large_ctx()
    benchmark(lambda: REGISTRY.evaluate_all(ctx, settings))
