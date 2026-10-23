"""CR-013 PR-013c: control typology registry (AC-16, INV-TYPE-1, INV-TYPE-2)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from graqle.assurance.control_types import (
    CONTROL_REGISTRY,
    ControlDescriptor,
    ControlType,
    assert_typology_invariants,
    classify,
)
from graqle.assurance.hard_gates import GATE_ORDER, default_registry

REPO = Path(__file__).resolve().parents[3]

# CR-013 §4.4 — the ids the registry must cover.
SPEC_IDS = {
    "TS-BLOCK",
    "GOV.review_threshold",
    "GOV.block_threshold",
    "GOV.secret_exposure_floor",
    "GOV.cumulative_radius_cap",
    "ART14.human_review_required_threshold",
    "DRACE.D",
    "DRACE.R",
    "DRACE.A",
    "DRACE.C",
    "DRACE.E",
    "DRACE.C.blocking_cap",
    "DRACE.total",
    "DRACE.grade",
    "CV.source_reliability",
    "CV.extraction_reliability",
    "CV.corroboration",
    "CV.temporal_validity",
    "CV.context_fit",
    "CV.reasoning_support",
    "CV.operational_reliability",
    "CV.extraction_reliability.floor",
    "CV.operational_reliability.activation_floor",
    "CV.corroboration.min",
    *GATE_ORDER,
    "CAP",
}


def _defines(tree: ast.Module, dotted: str) -> bool:
    scope: list[ast.stmt] = list(tree.body)
    for part in dotted.split("."):
        found: ast.stmt | None = None
        for node in scope:
            names: list[str] = []
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names = [node.name]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names = [node.target.id]
            elif isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if part in names:
                found = node
                break
        if found is None:
            return False
        scope = list(found.body) if isinstance(found, ast.ClassDef) else []
    return True


def _resolves(source: str) -> bool:
    path, _, symbol = source.partition(":")
    file = REPO / path
    return file.is_file() and _defines(ast.parse(file.read_text(encoding="utf-8")), symbol)


def test_registry_covers_every_spec_id_and_nothing_else() -> None:
    assert set(CONTROL_REGISTRY) == SPEC_IDS


def test_typology_invariants_hold() -> None:
    assert_typology_invariants()


def test_every_key_equals_its_control_id_and_has_one_type() -> None:
    for key, d in CONTROL_REGISTRY.items():
        assert key == d.control_id
        assert isinstance(d.control_type, ControlType)


def test_registry_is_read_only() -> None:
    with pytest.raises(TypeError):
        CONTROL_REGISTRY["NEW"] = CONTROL_REGISTRY["CAP"]  # type: ignore[index]


def test_classify_unregistered_raises_keyerror() -> None:
    with pytest.raises(KeyError, match="unregistered control"):
        classify("HG-99")
    assert classify("HG-05").control_type is ControlType.HARD


def test_drace_is_descriptive_in_dag_and_pillars_are_compensatory() -> None:
    assert classify("DRACE.total").control_type is ControlType.DESCRIPTIVE
    assert classify("DRACE.grade").control_type is ControlType.DESCRIPTIVE
    for pillar in "DRAE":
        d = classify(f"DRACE.{pillar}")
        assert d.control_type is ControlType.COMPENSATORY and not d.may_change_outcome
    assert classify("DRACE.C").control_type is ControlType.COMPENSATORY
    assert classify("DRACE.C.blocking_cap").control_type is ControlType.CAP


def test_hard_gate_ids_match_the_live_registry() -> None:
    live = {g.rule_id for g in default_registry().gates}
    hard = {k for k, d in CONTROL_REGISTRY.items() if k.startswith("HG-")}
    assert live == hard == set(GATE_ORDER)
    for k in hard:
        assert CONTROL_REGISTRY[k].control_type is ControlType.HARD


@pytest.mark.parametrize("control_id", sorted(SPEC_IDS))
def test_sources_resolve_to_real_symbols(control_id: str) -> None:
    source = CONTROL_REGISTRY[control_id].source
    assert _resolves(source), f"{control_id}: {source} does not resolve"


def test_no_hard_control_may_be_offset_and_only_hard_runs_first() -> None:
    for d in CONTROL_REGISTRY.values():
        if d.control_type is ControlType.HARD:
            assert d.evaluated_before_aggregate and not d.may_be_offset
        else:
            assert not d.evaluated_before_aggregate


def _broken(**changes: object) -> dict[str, ControlDescriptor]:
    base = classify("HG-01").model_dump()
    base.update(changes)
    d = ControlDescriptor(**base)
    return {d.control_id: d}


@pytest.mark.parametrize(
    "changes",
    [
        {"may_be_offset": True},
        {"evaluated_before_aggregate": False},
        {"may_change_outcome": False},
        {"control_type": ControlType.DESCRIPTIVE},
        {
            "control_type": ControlType.CAP,
            "may_be_offset": True,
            "evaluated_before_aggregate": False,
        },
        {
            "control_type": ControlType.COMPENSATORY,
            "may_be_offset": False,
            "evaluated_before_aggregate": False,
        },
    ],
    ids=["hard-offset", "hard-late", "hard-inert", "descriptive-acts", "cap-offset", "comp-rigid"],
)
def test_invariant_check_rejects_broken_descriptors(changes: dict[str, object]) -> None:
    with pytest.raises(AssertionError):
        assert_typology_invariants(_broken(**changes))


def test_registry_key_mismatch_is_rejected() -> None:
    d = classify("HG-01")
    with pytest.raises(AssertionError):
        assert_typology_invariants({"HG-02": d})


def test_public_doc_table_matches_registry() -> None:
    doc = (REPO / "docs/dag/control-typology.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| ([A-Za-z0-9_.\-]+) \| (\w+) \| `([^`]+)` \|$", doc, re.MULTILINE)
    documented = {cid: (ctype, src) for cid, ctype, src in rows if cid in SPEC_IDS}
    assert set(documented) == SPEC_IDS
    for cid, (ctype, src) in documented.items():
        d = CONTROL_REGISTRY[cid]
        assert (ctype, src) == (d.control_type.value, d.source)
