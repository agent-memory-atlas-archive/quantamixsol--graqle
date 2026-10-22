"""CR-013 AC-11 — HG-02 invalidated evidence."""

from __future__ import annotations

import pytest

from graqle.assurance.hard_gates import DependencyNodeRef, HG02InvalidatedEvidence

from ._builders import make_ctx, make_settings

GATE = HG02InvalidatedEvidence()
S = make_settings()


def _eval(*nodes: DependencyNodeRef):  # type: ignore[no-untyped-def]
    return GATE.evaluate(make_ctx(dependency_nodes=tuple(nodes)), S)


def test_no_dependencies_passes() -> None:
    assert _eval().passed


@pytest.mark.parametrize("recomputed", [None, False])
def test_dirty_without_recompute_fails(recomputed: bool | None) -> None:
    r = _eval(DependencyNodeRef(node_id="n1", dirty=True, recomputed=recomputed))
    assert not r.passed
    assert r.reason_codes[0].startswith("DAG-HG02-")


def test_recomputed_none_is_evidence_invalidated_code() -> None:
    r = _eval(DependencyNodeRef(node_id="n1", dirty=True, recomputed=None))
    assert r.reason_codes == ("DAG-HG02-EVIDENCE_INVALIDATED",)


def test_dirty_and_recomputed_passes() -> None:
    assert _eval(DependencyNodeRef(node_id="n1", dirty=True, recomputed=True)).passed


def test_status_fallback_when_dirty_is_none() -> None:
    bad = DependencyNodeRef(node_id="n1", status="INVALIDATED", recomputed=None)
    ok = DependencyNodeRef(node_id="n2", status="INVALIDATED", recomputed=True)
    assert not _eval(bad).passed
    assert _eval(ok).passed


def test_clean_node_passes() -> None:
    assert _eval(DependencyNodeRef(node_id="n1", dirty=False, status="VALID")).passed


def test_one_bad_node_among_good_fails() -> None:
    good = DependencyNodeRef(node_id="n1", dirty=False)
    bad = DependencyNodeRef(node_id="n2", dirty=True)
    assert not _eval(good, bad).passed
