"""CR-016 §5.4 / AC-16 — scope keys and identity decisions before merge (lifecycle rule L2)."""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from graqle.assurance.settings import DagSettings
from graqle.ontology.scope_resolution import (
    ScopeKey,
    assurance_canonical_id,
    compute_scope_key,
    resolve_identity,
)
from graqle.scanner.dedup.merge import _DEFAULT_PRIORITY

from ._assurance_fixtures import SALT
from ._assurance_fixtures import SUBSTITUTE_SCOPE_FIELDS as F

SETTINGS = DagSettings(config_salt=SALT)


class Index:
    def __init__(self, nodes: Sequence[Mapping[str, Any]], verdict: bool | None = None) -> None:
        self.nodes, self.verdict = list(nodes), verdict

    def lookup(self, canonical_id: str) -> Sequence[Mapping[str, Any]]:
        return [n for n in self.nodes if n["canonical_id"] == canonical_id]

    def user_decision(self, a_id: str, b_id: str) -> bool | None:
        return self.verdict


def _claim(node_id: str, alpha: str = "A", **extra: Any) -> dict[str, Any]:
    return {
        "id": node_id,
        "assurance_type": "Claim",
        "subject": "s",
        "predicate": "p",
        "object": "o",
        "f_alpha": alpha,
        "f_beta": "B",
        **extra,
    }


def _existing(node_id: str, alpha: str = "A", **extra: Any) -> dict[str, Any]:
    c = _claim(node_id, alpha, **extra)
    return {
        **c,
        "canonical_id": assurance_canonical_id(c),
        "scope_key": compute_scope_key(c, F).value,
    }


def _resolve(candidate: dict, index: Index) -> Any:
    return resolve_identity(candidate, index, _DEFAULT_PRIORITY, fields=F, settings=SETTINGS)


def test_scope_key_is_deterministic_and_normalised() -> None:
    a = compute_scope_key({"f_alpha": " A ", "f_beta": "B"}, F)
    b = compute_scope_key({"properties": {"f_alpha": "A", "f_beta": "B"}}, F)
    assert a == b and len(a.value) == 64
    assert compute_scope_key({"f_alpha": "A", "f_beta": "C"}, F) != a


def test_scope_key_requires_configured_fields() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        compute_scope_key({"f_alpha": "A"}, ())


def test_scope_key_repr_hides_the_private_field_list() -> None:
    assert "f_alpha" not in repr(ScopeKey(value="0" * 64, fields=F))


def test_create_when_no_canonical_match() -> None:
    d = _resolve(_claim("new"), Index([]))
    assert (d.action, d.target_id) == ("CREATE", None)


def test_coexist_when_same_identity_in_another_scope() -> None:
    d = _resolve(_claim("new", alpha="A"), Index([_existing("old", alpha="Z")]))
    assert (d.action, d.target_id) == ("COEXIST", "old")


def test_user_rejection_forces_create() -> None:
    d = _resolve(_claim("new"), Index([_existing("old")], verdict=False))
    assert d.action == "CREATE"


@pytest.mark.parametrize(
    ("cand_type", "target_type", "action", "reason"),
    [
        ("FUNCTION", "DOCUMENT", "MERGE_INTO", "candidate outranks target"),
        ("DOCUMENT", "FUNCTION", "MERGE_INTO", "target outranks candidate"),
        ("DOCUMENT", "DOCUMENT", "HOLD", "equal rank"),
    ],
)
def test_same_scope_decisions_follow_source_rank(cand_type, target_type, action, reason) -> None:  # type: ignore[no-untyped-def]
    d = _resolve(
        _claim("new", entity_type=cand_type), Index([_existing("old", entity_type=target_type)])
    )
    assert d.action == action and d.target_id == "old" and reason in d.reason


def test_decision_is_independent_of_index_order() -> None:
    nodes = [_existing(i, entity_type="DOCUMENT") for i in ("n3", "n1", "n2")]
    decisions = {
        _resolve(_claim("new", entity_type="DOCUMENT"), Index(list(p))).target_id
        for p in itertools.permutations(nodes)
    }
    assert decisions == {"n1"}


def test_determinism_record_is_complete() -> None:  # AC-16
    d = _resolve(_claim("new"), Index([]))
    assert d.rule_id == "CR016.identity" and d.rule_version
    assert d.inputs_hash.startswith("sha256:")
    assert d.config_version.startswith("sha256:")
    assert _resolve(_claim("new"), Index([])) == d


def test_canonical_id_rules_cover_every_class() -> None:
    for cls in (
        "Claim",
        "Evidence",
        "Policy",
        "Instruction",
        "Abstraction",
        "Decision",
        "Action",
        "Agent",
        "ProvenanceEvent",
    ):
        assert len(assurance_canonical_id({"assurance_type": cls})) == 64
    with pytest.raises(ValueError):
        assurance_canonical_id({"assurance_type": "Unknown"})
