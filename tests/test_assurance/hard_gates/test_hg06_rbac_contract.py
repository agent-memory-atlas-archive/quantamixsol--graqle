"""CR-013 AC-6 — HG-06 RBAC contract: deadline, exceptions and ImportError fail closed."""

from __future__ import annotations

import sys
import time

import pytest

import graqle.core.rbac as rbac
from graqle.assurance.hard_gates import HG06ActorAuthorized

from ._builders import make_ctx, make_settings

GATE = HG06ActorAuthorized()
UNAVAILABLE = ("DAG-HG06-RBAC_UNAVAILABLE",)


def test_passes_when_rbac_approves(settings) -> None:  # type: ignore[no-untyped-def]
    assert GATE.evaluate(make_ctx(), settings).passed


def test_false_answer_is_unauthorized(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(rbac, "check_approval", lambda a, t: (False, "no authority"))
    r = GATE.evaluate(make_ctx(required_tier="T3"), settings)
    assert not r.passed
    assert r.reason_codes == ("DAG-HG06-ACTOR_UNAUTHORIZED",)


def test_raising_rbac_is_unavailable(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    def boom(a: str, t: str) -> tuple[bool, str]:
        raise RuntimeError("registry corrupt")

    monkeypatch.setattr(rbac, "check_approval", boom)
    r = GATE.evaluate(make_ctx(), settings)
    assert not r.passed and r.reason_codes == UNAVAILABLE


def test_hung_rbac_times_out_within_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rbac, "check_approval", lambda a, t: (time.sleep(2.0), (True, ""))[1])
    s = make_settings(rbac_timeout_ms=100)
    t0 = time.monotonic()
    r = GATE.evaluate(make_ctx(), s)
    elapsed_ms = (time.monotonic() - t0) * 1000
    assert not r.passed and r.reason_codes == UNAVAILABLE
    assert elapsed_ms < 100 + 100  # AC-6: within timeout + 100 ms


def test_import_error_fails_closed(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    """Deliberate divergence from core/governance.py, which ALLOWS on ImportError."""
    monkeypatch.setitem(sys.modules, "graqle.core.rbac", None)
    r = GATE.evaluate(make_ctx(), settings)
    assert not r.passed and r.reason_codes == UNAVAILABLE


@pytest.mark.parametrize(
    "overrides",
    [{"actor_id": None}, {"actor_id": ""}, {"required_tier": None}, {"required_tier": "T9"}],
)
def test_missing_actor_or_tier_fails(overrides, settings) -> None:  # type: ignore[no-untyped-def]
    r = GATE.evaluate(make_ctx(**overrides), settings)
    assert not r.passed and r.decisive_conditions == ("actor_or_tier_missing",)


def test_non_tuple_answer_is_not_trusted(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(rbac, "check_approval", lambda a, t: True)
    assert not GATE.evaluate(make_ctx(), settings).passed


def test_rbac_is_rechecked_every_evaluation(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    answers = iter([(True, ""), (False, "revoked")])
    monkeypatch.setattr(rbac, "check_approval", lambda a, t: next(answers))
    assert GATE.evaluate(make_ctx(), settings).passed
    assert not GATE.evaluate(make_ctx(), settings).passed


def test_real_rbac_unknown_actor_cannot_approve_t3(
    monkeypatch: pytest.MonkeyPatch, settings
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.undo()  # drop the autouse stub; use the real default validator
    r = GATE.evaluate(make_ctx(actor_id="nobody-registered", required_tier="T3"), settings)
    assert not r.passed and r.reason_codes == ("DAG-HG06-ACTOR_UNAUTHORIZED",)
