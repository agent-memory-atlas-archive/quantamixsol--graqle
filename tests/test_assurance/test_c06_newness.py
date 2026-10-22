"""CR-017 PR-017a: AC-4 (C06, newness alone does not establish validity)."""

from __future__ import annotations

import inspect
import json

from graqle.assurance import conflicts
from graqle.assurance.conflicts import accept_correction, authority, independent_support_count, resolve

from ._conflict_fakes import (
    EARLIER,
    NOW,
    SUBST_CORROB_MIN,
    FakePersister,
    FakeReader,
    evidence,
    incoming_planner,
    make_cfg,
    node,
)
from .test_resolution_handlers import _record


def _signed_old_self_asserted_new(corrob_min=SUBST_CORROB_MIN):
    """Old: signed, code-rank, IAL2. New: newer, self-asserted, document-rank, IAL1."""
    reader = FakeReader()
    reader.agents["ag-hi"] = {"identity_assurance": "IAL2"}
    reader.nodes["old"] = node("old", entity_type="FUNCTION", authenticity="SIGNED", agent="ag-hi", asserted_at=EARLIER)
    reader.nodes["new"] = node("new", entity_type="DOCUMENT", authenticity="SELF_ASSERTED", asserted_at=NOW)
    rec = _record(a="new", b="old", contradiction_id="d" * 32)
    reader.add_record(rec)
    return reader, rec


def _run(reader, cfg=None):
    p = FakePersister()
    resolve(
        "d" * 32, "CORRECTS", actor="t", rationale_code="DAG-PV-SUPERSEDED", rationale_text="fix",
        reader=reader, persister=p, cfg=cfg or make_cfg(), winner_id="new",
        propagator=incoming_planner({"old": ["dep"]}), now=NOW,
    )
    (m,) = p.mutations.values()
    return m


def test_newer_self_asserted_correction_of_signed_claim_is_rejected_and_pending():
    reader, _ = _signed_old_self_asserted_new()
    m = _run(reader)
    writes = {w.node_id: w.set_props for w in m.node_writes}
    assert writes["new"]["lifecycle_status"] == "PROPOSED"      # newcomer not active
    assert "old" not in writes and not m.tasks                   # old untouched, nothing dirtied
    assert m.event.rationale_code == "DAG-PV-CORRECTION-REJECTED"
    assert m.event.resolution_kind is None
    (edge,) = m.edge_writes
    assert edge.kind == "CONTRADICTS" and edge.props["resolution_status"] == "PENDING"


def test_enough_independent_corroboration_accepts_the_correction():
    reader, _ = _signed_old_self_asserted_new()
    reader.support["new"] = [evidence(f"e{i}", f"root{i}") for i in range(SUBST_CORROB_MIN)]
    m = _run(reader)
    writes = {w.node_id: w.set_props for w in m.node_writes}
    assert writes["new"]["lifecycle_status"] == "ACTIVE"
    assert writes["old"]["lifecycle_status"] == "SUPERSEDED"
    assert writes["dep"]["lifecycle_status"] == "PENDING_RECOMPUTE"
    assert m.event.resolution_kind == "CORRECTS"


def test_one_short_of_corroboration_minimum_is_still_rejected():
    reader, _ = _signed_old_self_asserted_new()
    reader.support["new"] = [evidence(f"e{i}", f"root{i}") for i in range(SUBST_CORROB_MIN - 1)]
    assert _run(reader).event.rationale_code == "DAG-PV-CORRECTION-REJECTED"


def test_duplicate_evidence_with_one_canonical_hash_counts_once():
    reader = FakeReader()
    reader.support["new"] = [evidence(f"e{i}", "same-root") for i in range(SUBST_CORROB_MIN + 2)]
    assert independent_support_count("new", reader) == 1


def test_inactive_and_hashless_evidence_does_not_count():
    reader = FakeReader()
    reader.support["n"] = [evidence("e1", "r1", status="INVALIDATED"), {"id": "e2", "lifecycle_status": "ACTIVE"}]
    assert independent_support_count("n", reader) == 0


def test_authority_wins_without_corroboration():
    reader = FakeReader()
    reader.agents["ag"] = {"identity_assurance": "IAL2"}
    new = node("new", entity_type="FUNCTION", authenticity="SIGNED", agent="ag")
    old = node("old", entity_type="DOCUMENT")
    ok, _, decisive = accept_correction(new, old, reader, make_cfg())
    assert ok and decisive == ["authority(new) >= authority(old)"]


def test_authority_tuple_is_lexicographic_including_equal_ranks():
    reader = FakeReader()
    reader.agents["hi"] = {"identity_assurance": "IAL3"}
    cfg = make_cfg()
    same_rank_low = node("a", entity_type="DOCUMENT")
    same_rank_high = node("b", entity_type="DOCUMENT", agent="hi")
    assert authority(same_rank_high, reader, cfg) > authority(same_rank_low, reader, cfg)
    stronger_source = node("c", entity_type="FUNCTION")
    assert authority(stronger_source, reader, cfg) > authority(same_rank_high, reader, cfg)
    assert accept_correction(same_rank_low, same_rank_low, reader, cfg)[0]  # equal authority is accepted


def test_missing_or_unknown_agent_is_weakest_identity_assurance():
    reader = FakeReader()
    cfg = make_cfg()
    ghost = node("g", agent="not-registered")
    weird = node("w", agent="weird")
    reader.agents["weird"] = {"identity_assurance": "IAL9"}
    plain = node("p")
    assert authority(ghost, reader, cfg) == authority(plain, reader, cfg) == authority(weird, reader, cfg)


def test_unknown_source_type_ranks_weakest():
    reader = FakeReader()
    cfg = make_cfg()
    unknown = node("u", entity_type="MYSTERY")
    document = node("d", entity_type="DOCUMENT")
    assert authority(unknown, reader, cfg)[0] < authority(document, reader, cfg)[0]


def test_asserted_at_is_never_read_by_accept_correction():
    src = inspect.getsource(accept_correction) + inspect.getsource(authority) + inspect.getsource(independent_support_count)
    assert "asserted_at" not in src
    reader, _ = _signed_old_self_asserted_new()
    new, old = reader.nodes["new"], reader.nodes["old"]
    before = accept_correction(new, old, reader, make_cfg())
    new["asserted_at"], old["asserted_at"] = EARLIER, NOW   # swap which one is newer
    assert accept_correction(new, old, reader, make_cfg()) == before


def test_rejection_record_is_symbolic_and_carries_no_threshold_value():
    reader, _ = _signed_old_self_asserted_new()
    cfg = conflicts.ConflictConfig(corrob_min=7331, config_version="v", merge_priority={"code": 4101, "document": 4105})
    m = _run(reader, cfg)
    record = json.loads(m.event.authority_record)
    assert record["k"] == "K_CORROB_MIN"
    blob = json.dumps(m.event.model_dump())
    assert "7331" not in blob and "4101" not in blob and "4105" not in blob


def test_rejected_correction_replay_is_idempotent():
    reader, _ = _signed_old_self_asserted_new()
    p = FakePersister()
    for _ in range(2):
        resolve("d" * 32, "CORRECTS", actor="t", rationale_code="DAG-PV-SUPERSEDED", rationale_text="fix",
                reader=reader, persister=p, cfg=make_cfg(), winner_id="new",
                propagator=incoming_planner({}), now=NOW)
    assert len(p.mutations) == 1 and p.calls == 2
