"""CR-013 AC-9 (P-ORDER, INV-HG-3) — inputs_hash is permutation-invariant and stable."""

from __future__ import annotations

import subprocess
import sys

import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st

import graqle.assurance.hard_gates as hg
from graqle.assurance._hashing import inputs_hash, sorted_records

from ._builders import make_ctx, make_settings


def _rich_ctx(order: list[int] | None = None) -> hg.GateContext:
    contradictions = [
        hg.ContradictionRef(a_id="a", b_id="b", source_ids=("s2", "s1"), materiality=0.2),
        hg.ContradictionRef(a_id="d", b_id="c", source_ids=("s3",), materiality=None),
        hg.ContradictionRef(a_id="e", b_id="f", source_ids=(), coexists_rule_id="r1"),
    ]
    deps = [
        hg.DependencyNodeRef(node_id="n1", status="ACTIVE"),
        hg.DependencyNodeRef(node_id="n2", status=None, dirty=True),
        hg.DependencyNodeRef(node_id="n3", recomputed=False),
    ]
    events, sources, violations = ["e2", "e1", "e3"], ["s9", "s1"], ["v2", "v1"]
    if order is not None:
        contradictions = [contradictions[i % 3] for i in order]
        deps = [deps[i % 3] for i in order]
        events = [events[i % 3] for i in order]
    return make_ctx(
        contradictions=tuple(contradictions),
        dependency_nodes=tuple(deps),
        provenance_event_ids=tuple(events),
        provenance_source_ids=tuple(sources),
        policy_violations=tuple(violations),
        risk_level="HIGH",
    )


def _hashes(ctx: hg.GateContext) -> dict[str, str]:
    return {g.rule_id: inputs_hash(g.project(ctx)) for g in hg.default_registry().gates}


@h_settings(max_examples=100, deadline=None)
@given(perm=st.permutations([0, 1, 2]))
def test_permuting_list_fields_changes_no_hash(perm: list[int]) -> None:
    assert _hashes(_rich_ctx(perm)) == _hashes(_rich_ctx([0, 1, 2]))


def test_duplicate_records_hash_as_one() -> None:
    assert _hashes(_rich_ctx([0, 1, 2, 0, 0, 1])) == _hashes(_rich_ctx([0, 1, 2]))


def test_reversed_pair_hashes_as_the_same_pair() -> None:
    fwd = make_ctx(contradictions=(hg.ContradictionRef(a_id="a", b_id="b", materiality=0.5),))
    rev = make_ctx(contradictions=(hg.ContradictionRef(a_id="b", b_id="a", materiality=0.5),))
    assert _hashes(fwd)["HG-07"] == _hashes(rev)["HG-07"]


def test_sorted_records_tolerates_mixed_none_and_numbers() -> None:
    assert sorted_records([["x", None], ["x", 0.5], ["x", None]]) == [["x", 0.5], ["x", None]]


def test_thresholds_move_config_version_not_inputs_hash() -> None:
    ctx = make_ctx(poisoning_severity=0.3)
    a = hg.HG05Poisoning().evaluate(ctx, make_settings())
    b = hg.HG05Poisoning().evaluate(ctx, make_settings(hg05_poisoning_threshold=0.9))
    assert a.inputs_hash == b.inputs_hash
    assert a.config_version != b.config_version


def test_hash_differs_when_a_projected_input_changes() -> None:
    assert (
        _hashes(make_ctx(poisoning_severity=0.1))["HG-05"]
        != _hashes(make_ctx(poisoning_severity=0.2))["HG-05"]
    )


#: Golden hashes for ``_rich_ctx()``. A change here is a determinism break:
#: regenerate only together with a ``rule_version`` bump of the affected gate.
GOLDEN: dict[str, str] = {
    "HG-01": "sha256:63f1563915ee0efe58f39be43ec810bbf9a92811ceb644a508e4da82367d15d8",
    "HG-02": "sha256:8fafba982ff1ba60b0c7d5c19634c1a61adae16407cb6e359e456db0b83ce1ca",
    "HG-03": "sha256:2ae6e6d41a825162d005b281c738a4dadf2d204c78672f054020d4657f312c4f",
    "HG-04": "sha256:34a629fd8233d1f9fadc9826823559df9901fbfb4982f5b854639725ce8070da",
    "HG-05": "sha256:c6213684441efdcda525ce6776a256c539c1dcfdc72b13bda038e5f6be33d786",
    "HG-06": "sha256:3dc1c35900f1746384010893c5f7f54540d7d863920d99de769b4af202aeccd5",
    "HG-07": "sha256:f31435c8895ccde60cabc778c4f4186fb11ac4b24b56b08b82a8fe023fdbfefb",
}


_PROBE = """
import sys, json
sys.path.insert(0, {root!r})
from tests.test_assurance.hard_gates.test_inputs_hash import _rich_ctx, _hashes
print(json.dumps(_hashes(_rich_ctx())))
"""


def test_hashes_are_stable_across_processes() -> None:
    import json
    import pathlib

    root = str(pathlib.Path(__file__).resolve().parents[3])
    out = subprocess.run(
        [sys.executable, "-c", _PROBE.format(root=root)],
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    ).stdout
    assert json.loads(out) == _hashes(_rich_ctx())


@pytest.mark.parametrize("rule_id", hg.GATE_ORDER)
def test_golden_hashes(rule_id: str) -> None:
    assert _hashes(_rich_ctx())[rule_id] == GOLDEN[rule_id]
