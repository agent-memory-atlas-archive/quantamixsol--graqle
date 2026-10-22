"""DAG-2026 hard-gate sensitivity report (CR-013 §5.11, PR-013c).

For each hard gate, sweeps every scalar input of its projection while holding
the rest of a base context fixed, and records where the gate flips between
PASS and FAIL. Gates whose projection has no scalar input (HG-02, HG-04,
HG-06) are evaluated once at the base context and listed without a sweep.

Confidentiality rule (CR-013 §12): a sweep reveals thresholds. By default
the report is REDACTED: no swept value and no series is emitted, only that a
transition exists and its direction, as ``τ±``. The un-redacted report is
produced only when ``config_version(settings)`` equals the fingerprint the
caller passes as ``unredacted_fingerprint`` — the fingerprint of a test
substitute configuration. This module holds no threshold and no fingerprint.

Shipped as a library function only (CR-013 OQ-6: no CLI in this PR).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.sensitivity
# risk: LOW (impact radius: 0 existing callers)
# dependencies: graqle.assurance.{hard_gates,settings}
# constraints: never logs; redacts every swept value unless the caller proves
#   a test-substitute configuration by fingerprint (CR-013 AC-18)
# -- /graqle:intelligence --
from datetime import timedelta
from typing import Any

from graqle.assurance.hard_gates import (
    _RISK_ORDER,
    ContradictionRef,
    GateContext,
    HardGate,
    HardGateRegistry,
    PolicyRef,
)
from graqle.assurance.settings import DagSettings, config_version

__all__ = ["REDACTED", "sensitivity_report"]

#: Printed in place of every swept value while redaction is in force.
REDACTED = "τ±"

_WINDOW_DAYS = 30.0
_NO_SCALAR_INPUT = "no scalar input in this gate's projection"


def _grid(steps: int) -> list[float]:
    if steps < 2:
        raise ValueError("steps must be at least 2")
    return [i / (steps - 1) for i in range(steps)]


def _sweeps(base: GateContext, steps: int) -> dict[str, dict[str, list[tuple[Any, GateContext]]]]:
    """gate id → input name → [(value, context with that value)]."""
    unit = _grid(steps)
    policy = base.policy or PolicyRef(policy_id="sensitivity-policy")
    offsets = [(-_WINDOW_DAYS + 2 * _WINDOW_DAYS * u) for u in unit]

    def with_valid_until(days: float) -> GateContext:
        until = base.now + timedelta(days=days)
        return base.model_copy(update={"policy": policy.model_copy(update={"valid_until": until})})

    def with_contradiction(materiality: float) -> GateContext:
        pair = ContradictionRef(
            a_id="sensitivity-a",
            b_id="sensitivity-b",
            source_ids=("sensitivity-source",),
            materiality=materiality,
        )
        return base.model_copy(update={"contradictions": (pair,)})

    tiers = sorted(_RISK_ORDER, key=_RISK_ORDER.__getitem__)
    return {
        "HG-01": {"valid_until_offset_days": [(d, with_valid_until(d)) for d in offsets]},
        "HG-03": {"risk_tier": [(t, base.model_copy(update={"risk_level": t})) for t in tiers]},
        "HG-05": {
            "poisoning_severity": [
                (u, base.model_copy(update={"poisoning_severity": u})) for u in unit
            ]
        },
        "HG-07": {"materiality": [(u, with_contradiction(u)) for u in unit]},
    }


def _gate(registry: HardGateRegistry, rule_id: str) -> HardGate:
    return next(g for g in registry.gates if g.rule_id == rule_id)


def _transitions(series: list[tuple[Any, bool]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for (_, was), (value, now) in zip(series, series[1:], strict=False):
        if was != now:
            out.append({"direction": "PASS->FAIL" if was else "FAIL->PASS", "value": value})
    return out


def sensitivity_report(
    registry: HardGateRegistry,
    settings: DagSettings,
    base_ctx: GateContext,
    *,
    steps: int = 21,
    unredacted_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Sweep each scalar input of each gate and report the PASS/FAIL transitions.

    Returns ``{"redacted": bool, "gates": {rule_id: {...}}, "markdown": str}``.
    Gates fail closed on their own, so an error inside a gate shows up as a FAIL
    point in the sweep rather than as an exception here.
    """
    redacted = unredacted_fingerprint is None or config_version(settings) != unredacted_fingerprint
    sweeps = _sweeps(base_ctx, steps)
    gates: dict[str, Any] = {}
    for gate in registry.gates:
        entry: dict[str, Any] = {
            "inputs": {},
            "base_passed": gate.evaluate(base_ctx, settings).passed,
        }
        points = sweeps.get(gate.rule_id)
        if not points:
            entry["note"] = _NO_SCALAR_INPUT
        for name, cases in (points or {}).items():
            series = [(value, gate.evaluate(ctx, settings).passed) for value, ctx in cases]
            transitions = _transitions(series)
            if redacted:
                transitions = [{**t, "value": REDACTED} for t in transitions]
            record: dict[str, Any] = {"transitions": transitions}
            record["series"] = None if redacted else series
            entry["inputs"][name] = record
        gates[gate.rule_id] = entry
    return {"redacted": redacted, "gates": gates, "markdown": _markdown(gates, redacted)}


def _markdown(gates: dict[str, Any], redacted: bool) -> str:
    lines = [
        "| gate | input | base | transitions |",
        "|---|---|---|---|",
    ]
    for rule_id, entry in gates.items():
        base = "PASS" if entry["base_passed"] else "FAIL"
        if not entry["inputs"]:
            lines.append(f"| {rule_id} | ({entry['note']}) | {base} | - |")
        for name, record in entry["inputs"].items():
            found = "; ".join(f"{t['direction']} at {t['value']}" for t in record["transitions"])
            lines.append(f"| {rule_id} | {name} | {base} | {found or 'none'} |")
    if redacted:
        lines.append("")
        lines.append(f"Values redacted ({REDACTED}); thresholds are private configuration.")
    return "\n".join(lines)
