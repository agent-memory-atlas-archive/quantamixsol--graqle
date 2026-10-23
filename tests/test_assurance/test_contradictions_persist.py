"""CR-017 PR-017a: AC-1 (detector untouched), AC-2 (persist exactly once), AC-16 (determinism record)."""

from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest

from graqle.assurance.conflicts import (
    GLOBAL_SCOPE_KEY,
    ConflictConfig,
    ConflictError,
    persist_contradictions,
    to_records,
)
from graqle.scanner.dedup import contradictions as dedup_contradictions
from graqle.scanner.dedup.contradictions import detect_contradictions

from ._conflict_fakes import SUBST_CORROB_MIN, SUBST_PRIORITY, FakePersister, make_cfg

NODES = {
    "n_code": {"id": "n_code", "label": "Session timeout", "entity_type": "FUNCTION", "properties": {"ttl": 3600, "strict": True, "mode": "alpha"}},
    "n_doc": {"id": "n_doc", "label": "session timeout", "entity_type": "DOCUMENT", "properties": {"ttl": 1800, "strict": False, "mode": "beta"}},
}
GOLDEN = [
    {"type": "numeric_mismatch", "label": "session timeout", "key": "ttl", "value_a": 3600, "value_b": 1800, "source_a": "n_code (code)", "source_b": "n_doc (document)"},
    # bool is an int subclass, so the unchanged detector reports it as numeric_mismatch
    {"type": "numeric_mismatch", "label": "session timeout", "key": "strict", "value_a": True, "value_b": False, "source_a": "n_code (code)", "source_b": "n_doc (document)"},
    {"type": "value_mismatch", "label": "session timeout", "key": "mode", "value_a": "alpha", "value_b": "beta", "source_a": "n_code (code)", "source_b": "n_doc (document)"},
]


def _scope(node):
    return "scope-x"


def _by_key(detections):
    return sorted(detections, key=lambda d: d["key"])


def test_ac1_detector_output_golden_unchanged():
    assert _by_key(detect_contradictions(NODES)) == _by_key(GOLDEN)


def test_ac1_to_records_does_not_mutate_detector_output():
    detections = detect_contradictions(NODES)
    snapshot = json.dumps(detections, sort_keys=True)
    to_records(detections, NODES, _scope)
    assert json.dumps(detections, sort_keys=True) == snapshot


def test_ac1_importing_assurance_package_does_not_load_conflicts():
    code = "import sys, graqle.assurance; sys.exit(1 if 'graqle.assurance.conflicts' in sys.modules else 0)"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


def test_scanner_to_records_delegates():
    recs = dedup_contradictions.to_records(detect_contradictions(NODES), NODES, _scope)
    assert len(recs) == len(GOLDEN)


def test_ac2_one_edge_per_detection_and_deterministic_ids():
    recs = to_records(detect_contradictions(NODES), NODES, _scope)
    again = to_records(detect_contradictions(NODES), NODES, _scope)
    assert [r.contradiction_id for r in recs] == [r.contradiction_id for r in again]
    assert len({r.contradiction_id for r in recs}) == len(GOLDEN)
    p = FakePersister()
    persist_contradictions(recs, p, make_cfg())
    contradicts = [e for e in p.edges.values() if e["kind"] == "CONTRADICTS"]
    assert len(contradicts) == len(GOLDEN)
    assert {e["resolution_status"] for e in contradicts} == {"PENDING"}


def test_ac2_repersist_creates_no_new_edges_or_events():
    recs = to_records(detect_contradictions(NODES), NODES, _scope)
    p = FakePersister()
    persist_contradictions(recs, p, make_cfg())
    edges, events = dict(p.edges), dict(p.events)
    receipts = persist_contradictions(recs, p, make_cfg())
    assert all(r.replayed for r in receipts)
    assert p.edges == edges and p.events == events


def test_contradiction_id_is_symmetric_in_pair():
    swapped = {
        "type": "numeric_mismatch", "label": "session timeout", "key": "ttl", "value_a": 1800, "value_b": 3600,
        "source_a": "n_doc (document)", "source_b": "n_code (code)",
    }
    forward = to_records([GOLDEN[0]], NODES, _scope)[0]
    backward = to_records([swapped], NODES, _scope)[0]
    assert forward.contradiction_id == backward.contradiction_id
    assert (forward.node_a, forward.node_b) == (backward.node_a, backward.node_b)
    assert (forward.value_a_hash, forward.value_b_hash) == (backward.value_a_hash, backward.value_b_hash)


def test_raw_values_are_hashed_not_persisted():
    recs = to_records(detect_contradictions(NODES), NODES, _scope)
    p = FakePersister()
    persist_contradictions(recs, p, make_cfg())
    blob = json.dumps({"edges": p.edges, "events": {k: v.model_dump() for k, v in p.events.items()}})
    for raw in ("alpha", "beta"):
        assert raw not in blob


def test_cross_scope_pair_uses_global_scope_key():
    scopes = {"n_code": "scope-a", "n_doc": "scope-b"}
    recs = to_records(GOLDEN[:1], NODES, lambda n: scopes[n["id"]])
    assert recs[0].scope_key == GLOBAL_SCOPE_KEY


def test_unparseable_source_and_unknown_node_fail_closed():
    bad = dict(GOLDEN[0], source_a="no-type-suffix")
    with pytest.raises(ConflictError):
        to_records([bad], NODES, _scope)
    unknown = dict(GOLDEN[0], source_a="ghost (code)")
    with pytest.raises(ConflictError):
        to_records([unknown], NODES, _scope)
    for bad_scope in (lambda n: None, lambda n: "", lambda n: 5):
        with pytest.raises(ConflictError):
            to_records(GOLDEN[:1], NODES, bad_scope)


def test_ac16_determinism_record_and_no_threshold_values():
    cfg = ConflictConfig(corrob_min=7331, config_version="cfg-v", merge_priority=dict(SUBST_PRIORITY))
    recs = to_records(detect_contradictions(NODES), NODES, _scope)
    p = FakePersister()
    persist_contradictions(recs, p, cfg)
    for ev in p.events.values():
        d = ev.model_dump()
        for field in ("inputs_hash", "rule_id", "rule_version", "config_version", "decisive_conditions", "idempotency_key"):
            assert d[field], field
        assert ev.event_id == "pev_" + ev.idempotency_key[:26]
        blob = json.dumps(d)
        # whole-token match: a bare substring test collides with digits inside hex hashes
        assert not re.search(r"(?<![0-9A-Za-z])7331(?![0-9A-Za-z])", blob)
        assert not any(re.search(rf"(?<![0-9A-Za-z]){v}(?![0-9A-Za-z])", blob) for v in SUBST_PRIORITY.values())


def test_config_rejects_zero_and_non_integer_corroboration_minimum():
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ConflictError):
            ConflictConfig(corrob_min=bad, config_version="v")  # type: ignore[arg-type]
    assert ConflictConfig(corrob_min=SUBST_CORROB_MIN, config_version="v").rank("unknown-type") > max(
        ConflictConfig(corrob_min=1, config_version="v").merge_priority.values()
    )
