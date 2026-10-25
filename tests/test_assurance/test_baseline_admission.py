"""CR-DAG-087-1 PR-B: baseline admission rule DAG-RT-BASELINE-ADMIT and the default provider.

Part delivered here: the default provider, the baseline rule and the persisted hash-chained
provenance. The hook and start-up self-check are PR-A; the built-wheel test is PR-C.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from graqle.assurance import adapter, baseline, default_provider
from graqle.assurance import hard_gates as hg
from graqle.assurance.baseline import BASELINE_RULE_ID, NO_EVIDENCE_CODE, BaselineAdmissionGate
from graqle.assurance.gate import EvaluationContext, GateCandidate
from graqle.assurance.hard_gates import default_registry
from graqle.assurance.outcomes import GateOutcome
from graqle.assurance.provenance_recorder import ProvenanceUnavailableError
from graqle.assurance.provenance_store import FileProvenanceStore
from graqle.assurance.reason_codes import REGISTRY
from graqle.assurance.routing_settings import BaselineRoutingSettings, RoutingSettings
from graqle.config.exceptions import ConfigurationError

from .hard_gates._builders import make_settings
from .test_provenance_recorder import Rig

_NUMERIC_KEYS = (
    "decision_score",
    "trj_reliability",
    "trajectory_reliability",
    "residual_risk",
    "confidence_vector",
)


def _gate(tmp_path: Path, recorder=None, **rig_over) -> tuple[BaselineAdmissionGate, Rig]:
    rig = Rig(tmp_path, **rig_over)
    gate = BaselineAdmissionGate(
        registry=default_registry(),
        settings=make_settings(),
        recorder=recorder or rig.rec,
        routing=BaselineRoutingSettings(),
        clock=rig.clock,  # the recorder's fixed clock, so occurred_at and captured_at agree
    )
    return gate, rig


def _call(risk: str = "LOW", impact: int | None = 0, actor: str = "agent-1"):
    candidate = GateCandidate.from_check_kwargs(
        file_path="a.py", action="edit", actor=actor, risk_level=risk
    )
    ctx = EvaluationContext(
        session_id="baseline",
        actor_id=actor,
        history=None,
        checkpoint=None,
        legacy_result=SimpleNamespace(impact_radius=impact),
    )
    return candidate, ctx


@pytest.fixture(autouse=True)
def _rbac_ok(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(hg, "_rbac_with_deadline", lambda *_a, **_k: "ok")


def _events(tmp_path: Path) -> list[dict]:
    store = Path(tmp_path) / "events"
    return [json.loads(p.read_text()) for p in sorted(store.glob("evt_*.json"))]


def test_low_risk_zero_impact_all_gates_pass_executes_and_is_recorded(tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path)
    verdict = gate.evaluate(*_call())
    assert verdict.outcome is GateOutcome.EXECUTE
    assert verdict.decisive_rule == BASELINE_RULE_ID
    assert "DAG-TR-010-EVALUATION_ERROR" not in verdict.reason_codes
    assert len(verdict.verdict.hard_gate_results) == 7  # all seven gates evaluated
    events = _events(tmp_path)
    assert len(events) == 1
    refs = events[0]["inputs"]["policy_refs"]
    for mandatory in (
        "vector_source:BASELINE",
        "evidence_tier:BASELINE",
        "decision_path:BASELINE_ADMISSION",
        f"rule:{BASELINE_RULE_ID}",
        "validation_status:BASELINE_GATES_PASSED",
    ):
        assert mandatory in refs
    assert events[0]["assessment"]["outcome"] == "EXECUTE"
    assert events[0]["ordering"]["previous_event_hash"] == "0" * 64  # genesis


def test_events_are_chained_and_survive_a_restart(tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path)
    gate.evaluate(*_call())
    gate.evaluate(*_call(impact=3))
    reread = FileProvenanceStore(tmp_path / "events")  # a fresh store object, same disk
    assert reread is not None
    events = sorted(_events(tmp_path), key=lambda e: e["ordering"]["sequence_number"])
    assert [e["ordering"]["sequence_number"] for e in events] == [0, 1]
    assert events[1]["ordering"]["previous_event_hash"] == events[0]["integrity"]["canonical_hash"]


def test_baseline_events_and_verdict_carry_no_numeric_score_fields(tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path)
    verdict = gate.evaluate(*_call())
    v = verdict.verdict
    assert v.trajectory_reliability is None and v.residual_risk is None
    assert v.confidence_vector is None
    text = json.dumps(_events(tmp_path)) + json.dumps(verdict.public_view())
    for key in _NUMERIC_KEYS:
        assert f'"{key}"' not in text.replace('"confidence_vector_ref": null', "")


@pytest.mark.parametrize("risk", ["MEDIUM", "HIGH"])
def test_medium_and_above_is_not_admitted_on_baseline(tmp_path: Path, risk: str) -> None:
    gate, _ = _gate(tmp_path)
    verdict = gate.evaluate(*_call(risk=risk))
    # HIGH is also closed by HG-03 (no provenance supplied): REJECT, never EXECUTE.
    assert verdict.outcome in (GateOutcome.HOLD, GateOutcome.REJECT)
    if risk == "MEDIUM":
        assert verdict.outcome is GateOutcome.HOLD
        assert NO_EVIDENCE_CODE in verdict.reason_codes
    assert _events(tmp_path)[0]["assessment"]["outcome"] == verdict.outcome.value


def test_unknown_risk_is_never_executed(tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path)
    assert gate.evaluate(*_call(risk="???")).outcome is not GateOutcome.EXECUTE


@pytest.mark.parametrize("impact", [1, None])
def test_nonzero_or_unknown_impact_holds_with_no_evidence(tmp_path: Path, impact) -> None:
    gate, _ = _gate(tmp_path)
    verdict = gate.evaluate(*_call(impact=impact))
    assert verdict.outcome is GateOutcome.HOLD
    assert verdict.reason_codes == [NO_EVIDENCE_CODE]


def test_failing_hard_gate_closes_and_is_recorded_independent_of_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hg, "_rbac_with_deadline", lambda *_a, **_k: "actor_unauthorized")
    gate, _ = _gate(tmp_path)
    verdict = gate.evaluate(*_call())
    assert verdict.outcome is GateOutcome.REJECT
    assert "DAG-HG06-ACTOR_UNAUTHORIZED" in verdict.reason_codes
    event = _events(tmp_path)[0]
    assert event["assessment"]["outcome"] == "REJECT"
    assert any(not g["passed"] for g in event["assessment"]["hard_gate_results"])
    assert "validation_status:BASELINE_GATES_FAILED" in event["inputs"]["policy_refs"]


def test_every_gate_is_evaluated_even_after_an_early_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hg, "_rbac_with_deadline", lambda *_a, **_k: "rbac_unavailable")
    gate, _ = _gate(tmp_path)
    verdict = gate.evaluate(*_call(actor=""))
    assert len(verdict.verdict.hard_gate_results) == 7
    assert verdict.outcome is GateOutcome.REJECT


class _FailingRecorder:
    def record(self, **_kw):
        raise ProvenanceUnavailableError("DAG-PV-RECORD-FAILED", "disk full")


def test_write_failure_never_executes_and_is_reported(tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path, recorder=_FailingRecorder())
    verdict = gate.evaluate(*_call())
    assert verdict.outcome is GateOutcome.HOLD
    assert "DAG-TR-015-PROVENANCE_EMIT_FAILED" in verdict.reason_codes
    assert verdict.verdict.evaluation_errors == ["provenance: DAG-PV-RECORD-FAILED"]


def test_write_failure_on_a_rejection_stays_a_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hg, "_rbac_with_deadline", lambda *_a, **_k: "actor_unauthorized")
    gate, _ = _gate(tmp_path, recorder=_FailingRecorder())
    verdict = gate.evaluate(*_call())
    assert verdict.outcome is GateOutcome.REJECT
    assert verdict.verdict.evaluation_errors


def test_unexpected_exception_fails_closed(tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path)
    gate._registry = SimpleNamespace(evaluate_all=lambda *_a: (_ for _ in ()).throw(RuntimeError("x")))
    verdict = gate.evaluate(*_call())
    assert verdict.outcome is GateOutcome.ESCALATE


def test_no_evidence_code_is_registered() -> None:
    assert NO_EVIDENCE_CODE in REGISTRY


# -- scope-lock: numeric routing path is unchanged ------------------------------------------


def test_numeric_routing_path_still_raises_without_env() -> None:
    with pytest.raises(ConfigurationError) as err:
        RoutingSettings.from_env({})
    assert "GRAQLE_DAG_TRAJECTORY_FLOOR_LOW" in str(err.value)


def test_symbolic_defaults_are_unreachable_from_the_numeric_path() -> None:
    assert not hasattr(BaselineRoutingSettings(), "trajectory_floor")
    assert not hasattr(BaselineRoutingSettings(), "residual_risk_budget")
    assert not isinstance(BaselineRoutingSettings(), RoutingSettings)
    with pytest.raises(ConfigurationError):
        RoutingSettings.from_env({"GRAQLE_DAG_TIER_AUTOMATION_MAX": "LOW"})


def test_baseline_ceiling_is_low_and_env_overridable() -> None:
    assert BaselineRoutingSettings.from_env({}).tier_automation_max.value == "LOW"
    assert BaselineRoutingSettings.from_env({"GRAQLE_DAG_TIER_AUTOMATION_MAX": "medium"}).tier_automation_max.value == "MEDIUM"
    with pytest.raises(ConfigurationError):
        BaselineRoutingSettings.from_env({"GRAQLE_DAG_TIER_AUTOMATION_MAX": "bogus"})


def test_gate_py_is_not_consulted_by_the_baseline_module() -> None:
    src = Path(baseline.__file__).read_text()
    assert "route(" not in src.replace("def route", "")


# -- default provider ------------------------------------------------------------------------


def test_provider_hands_out_the_gate_and_a_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gate, _ = _gate(tmp_path)
    monkeypatch.setattr(default_provider, "_build_gate", lambda: gate)
    provider = default_provider.build_default_provider()
    legacy = SimpleNamespace(impact_radius=0)
    got_gate, ctx = provider(object(), legacy, actor="alice", file_path="a.py")
    assert got_gate is gate and ctx.actor_id == "alice" and ctx.legacy_result is legacy


def test_provider_build_failure_is_a_startup_error_naming_register_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom():
        raise ConfigurationError("signing key missing")

    monkeypatch.setattr(default_provider, "_build_gate", boom)
    with pytest.raises(adapter.RuntimeNotRegisteredError, match="register_runtime"):
        default_provider.build_default_provider()


def test_provider_with_flag_on_and_nothing_configured_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in list(__import__("os").environ):
        if name.startswith("GRAQLE_DAG_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    with pytest.raises(adapter.RuntimeNotRegisteredError, match="register_runtime"):
        default_provider.build_default_provider()


def test_ensure_runtime_registered_installs_the_packaged_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    gate, _ = _gate(tmp_path)
    monkeypatch.setattr(default_provider, "_build_gate", lambda: gate)
    previous = adapter._runtime_provider
    adapter.register_runtime(None)
    try:
        adapter.ensure_runtime_registered()
        assert adapter._runtime_provider is not None
    finally:
        adapter.register_runtime(previous)
