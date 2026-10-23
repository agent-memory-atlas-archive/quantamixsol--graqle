"""CR-015 AC-9, AC-10, AC-13: with the flag unset the dispatcher is invisible (PR-015b).

The golden file is the 64-case ``GateResult.to_dict()`` capture recorded on the v0.83.0
tag before the dispatcher existed (committed by CR-012 PR-012c, pinned there by sha256).
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from graqle.core.governance import GateResult, GovernanceConfig, GovernanceMiddleware

_GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "gate_result_golden_v0830.json"
_NINE_KEYS = {
    "tier", "blocked", "requires_approval", "gate_score", "reason",
    "warnings", "bypass_allowed", "risk_level", "impact_radius",
}


@pytest.fixture(autouse=True)
def _flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    GovernanceMiddleware._cumulative.clear()


class TestAC9FlagOffByteIdentity:
    def test_dispatcher_reproduces_every_golden_result(self) -> None:
        cases = json.loads(_GOLDEN.read_text(encoding="utf-8"))
        assert len(cases) >= 40
        mismatches: list[str] = []
        for case in cases:
            p = case["in"]
            GovernanceMiddleware._cumulative.clear()
            GovernanceMiddleware._state_loaded = True
            mw = GovernanceMiddleware(config=GovernanceConfig())
            out = mw.check(
                diff=p["diff"], file_path="src/mod.py", risk_level=p["risk"],
                impact_radius=p["radius"], approved_by=p["approved_by"], action="edit", actor=p["actor"],
            )
            if json.dumps(out.to_dict(), sort_keys=True) != json.dumps(case["out"], sort_keys=True):
                mismatches.append(str(p))
        assert not mismatches, mismatches[:5]

    def test_flag_off_check_is_exactly_the_legacy_body(self) -> None:
        mw = GovernanceMiddleware(config=GovernanceConfig())
        calls: list[dict] = []
        real = mw._check_legacy

        def spy(**kw: object) -> GateResult:
            calls.append(kw)
            return real(**kw)

        mw._check_legacy = spy  # type: ignore[method-assign]
        out = mw.check(diff="+ x = 1", risk_level="LOW", actor="alice")
        assert len(calls) == 1 and calls[0]["diff"] == "+ x = 1" and out.tier == "T1"

    @pytest.mark.parametrize("value", ["", "0", "false", "off", "no", "maybe", "2"])
    def test_non_truthy_flag_values_stay_on_the_legacy_path(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", value)
        mw = GovernanceMiddleware(config=GovernanceConfig())
        out = mw.check(diff="+ x = 1", risk_level="LOW", actor="alice")
        assert not any(w.startswith("[DAG]") for w in out.warnings)


class TestAC10ImportGraph:
    def test_adapter_and_gate_are_not_imported_by_a_flag_off_check(self) -> None:
        code = textwrap.dedent(
            """
            import os, sys
            os.environ.pop("GRAQLE_DAG_ENABLED", None)
            from graqle.core.governance import GovernanceConfig, GovernanceMiddleware
            GovernanceMiddleware._state_loaded = True
            mw = GovernanceMiddleware(config=GovernanceConfig())
            mw.check(diff="+ x = 1", risk_level="LOW", actor="alice")
            bad = [m for m in ("graqle.assurance.adapter", "graqle.assurance.gate") if m in sys.modules]
            print("LOADED=" + ",".join(bad))
            """
        )
        done = subprocess.run(
            [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120,
            cwd=Path(__file__).resolve().parents[2],
            env={"PATH": "", "PYTHONPATH": str(Path(__file__).resolve().parents[2])},
        )
        assert done.returncode == 0, done.stderr[-500:]
        assert "LOADED=" in done.stdout and done.stdout.strip().endswith("LOADED="), done.stdout


class TestAC13KeySet:
    def test_to_dict_has_exactly_the_nine_keys(self) -> None:
        r = GateResult(tier="T1", blocked=False, requires_approval=False, gate_score=0.0, reason="r")
        assert set(r.to_dict()) == _NINE_KEYS
