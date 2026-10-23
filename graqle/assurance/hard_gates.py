"""DAG-2026 hard gates HG-01 … HG-07 and their registry (CR-013, PR-013a).

Seven boolean, non-compensatory gates evaluated **before** any weighted
aggregate. Each gate tests one disqualifying condition and returns a
:class:`HardGateResult`; a FAIL on any gate can never be offset by a score
elsewhere (the ``GateVerdict`` validator makes EXECUTE impossible, CR-012).

Invariants (CR-013 §2.2):

* INV-HG-2 — :meth:`HardGateRegistry.evaluate_all` evaluates EVERY gate, even
  after an earlier FAIL, so reason codes are complete. The fixed order of
  :data:`GATE_ORDER` only decides :func:`decisive_rule`; it creates no
  precedence between gates.
* INV-HG-3 — a result is a pure function of the gate's projection, its rule
  version and ``config_version``; ``inputs_hash`` records the projection.
* INV-HG-4 — fail-closed. A missing input, a dependency error, an exception or
  an exceeded deadline is FAIL with ``error`` set and
  ``DAG-RP-EVALUATION_ERROR``; nothing can PASS by exception.

All seven gates are live: HG-02 and HG-04 (PR-013b) read the CR-017
invalidation fields of ``DependencyNodeRef`` and the CR-018
``approved_args_*`` fields of ``GateContext``, and still fail closed while
those fields are absent. Nothing here is called by ``GovernanceMiddleware``; the gate is
consumed by ``DecisionAssuranceGate.evaluate()`` (CR-015) only.

Configuration rule (CR-013 §12): thresholds reach a gate only through a frozen
:class:`~graqle.assurance.settings.DagSettings`. No threshold value is ever
projected, hashed in clear, logged, or placed in an error string.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.hard_gates
# risk: MEDIUM (impact radius: 0 existing callers -- consumed by CR-015 later)
# dependencies: pydantic, graqle.assurance.{_hashing,reason_codes,settings},
#   graqle.core.rbac (lazy, inside HG-06 only)
# constraints: never imported by graqle.governance.*; core/rbac.py and
#   intelligence/governance/drace.py stay untouched (CR-013 AC-21)
# -- /graqle:intelligence --
import hmac
import threading
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from graqle.assurance._hashing import inputs_hash, sorted_ids, sorted_records
from graqle.assurance.reason_codes import validate as _validate_codes
from graqle.assurance.settings import ConfigurationError, DagSettings, config_version

__all__ = [
    "GATE_ORDER",
    "ContradictionRef",
    "DependencyNodeRef",
    "GateContext",
    "HardGate",
    "HardGateRegistry",
    "HardGateResult",
    "HG01MandatoryPolicy",
    "HG02InvalidatedEvidence",
    "HG03ProvenanceForHighImpact",
    "HG04ArgsBinding",
    "HG05Poisoning",
    "HG06ActorAuthorized",
    "HG07MaterialContradiction",
    "PolicyRef",
    "all_passed",
    "decisive_rule",
    "default_registry",
]

#: Fixed evaluation order G (CR-013 §2.1). Decides the decisive rule only.
GATE_ORDER: tuple[str, ...] = ("HG-01", "HG-02", "HG-03", "HG-04", "HG-05", "HG-06", "HG-07")

_EVALUATION_ERROR = "DAG-RP-EVALUATION_ERROR"
_Severity = Literal["CRITICAL", "FAIL"]

#: Impact-tier order; mirrors ``core/governance.py`` ``_RISK_ORDER`` by copy
#: (CR-013 OQ-2: copy + parity test, so assurance does not import
#: ``core/governance.py``). Unknown or missing risk ⇒ CRITICAL (fail-safest).
_RISK_ORDER: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_VALID_TIERS: frozenset[str] = frozenset({"T1", "T2", "T3"})


# ── input model (CR-013 §4.1) ────────────────────────────────────────────────


class PolicyRef(BaseModel):
    """The policy governing the action, resolved by the caller BY SCOPE."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    #: CONTRADICTS partners that lack a COEXISTS_WITH ruling (pre-materialised
    #: by the caller / CR-017).
    open_contradiction_ids: tuple[str, ...] = ()


class DependencyNodeRef(BaseModel):
    """A node the action depends on (consumed by HG-02 from PR-013b)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    status: str | None = None
    dirty: bool | None = None
    recomputed: bool | None = None


class ContradictionRef(BaseModel):
    """A contradiction between two items (consumed by HG-07)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    a_id: str
    b_id: str
    #: Canonical source identities behind a and b (P-CORR de-duplication).
    source_ids: tuple[str, ...] = ()
    #: ``None`` ⇒ treated as material (fail-closed).
    materiality: float | None = Field(default=None, ge=0.0, le=1.0, allow_inf_nan=False)
    #: COEXISTS_WITH rule id when the contradiction is explicitly resolved.
    coexists_rule_id: str | None = None


class GateContext(BaseModel):
    """Every input to one evaluation; immutable for that evaluation.

    Callers materialise all slices up front: no gate opens a driver, walks a
    graph or reads the environment (CR-013 §2.5, §4.5).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    now: datetime
    governance_scope: str
    policy: PolicyRef | None = None
    policy_violations: tuple[str, ...] = ()
    dependency_nodes: tuple[DependencyNodeRef, ...] = ()
    risk_level: str | None = None
    provenance_event_ids: tuple[str, ...] = ()
    provenance_source_ids: tuple[str, ...] = ()
    approved_args_hash: str | None = None
    approved_args_algo: str | None = None
    actual_args_hash: str | None = None
    actual_args_algo: str | None = None
    poisoning_severity: float | None = Field(default=None, ge=0.0, le=1.0, allow_inf_nan=False)
    actor_id: str | None = None
    required_tier: str | None = None
    contradictions: tuple[ContradictionRef, ...] = ()
    #: DESCRIPTIVE input only (DRACE total) — never gated on.
    drace_total: float | None = Field(default=None, ge=0.0, le=1.0, allow_inf_nan=False)
    trace_id: str | None = None


# ── result model and protocol (CR-013 §4.2) ─────────────────────────────────


class HardGateResult(BaseModel):
    """One gate's verdict plus its determinism record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    rule_version: str
    severity: _Severity
    passed: bool
    #: Names of the atomic predicates that fired — names only, never values.
    decisive_conditions: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    inputs_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    config_version: str
    evaluated_at: datetime
    duration_ms: float = Field(ge=0.0)
    #: Exception type (and a fixed, value-free description); non-None ⇒ FAIL.
    error: str | None = None

    @field_validator("reason_codes")
    @classmethod
    def _codes_registered(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_codes(list(value)))

    @model_validator(mode="after")
    def _consistency(self) -> HardGateResult:
        if self.error is not None and self.passed:
            raise ValueError("a hard gate with error must not pass")
        if self.passed and (self.decisive_conditions or self.reason_codes):
            raise ValueError("a passing hard gate carries no conditions or reason codes")
        if not self.passed and not self.reason_codes:
            raise ValueError("a failing hard gate must carry at least one reason code")
        return self


@runtime_checkable
class HardGate(Protocol):
    rule_id: str
    version: str
    severity: _Severity

    def project(self, ctx: GateContext) -> dict[str, Any]: ...

    def evaluate(self, ctx: GateContext, settings: DagSettings) -> HardGateResult: ...


# ── shared evaluation wrapper (CR-013 §5.2) ─────────────────────────────────


class _BaseGate:
    """Deadline, hashing, code mapping and fail-closed handling for one gate."""

    rule_id: ClassVar[str]
    version: ClassVar[str] = "1.0.0"
    severity: ClassVar[_Severity] = "CRITICAL"
    #: predicate name → registered reason code
    _CODES: ClassVar[dict[str, str]] = {}
    #: extra codes attached when the gate errors (beyond EVALUATION_ERROR)
    _ERROR_CODES: ClassVar[tuple[str, ...]] = ()

    def project(self, ctx: GateContext) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        raise NotImplementedError  # pragma: no cover - abstract

    def evaluate(self, ctx: GateContext, settings: DagSettings) -> HardGateResult:
        # A configuration that cannot be fingerprinted refuses the whole
        # evaluation (ConfigurationError propagates); it is never a per-gate FAIL.
        cfg_v = config_version(settings)
        t0 = time.monotonic()
        deadline = t0 + settings.gate_timeout_ms / 1000.0
        try:
            h = inputs_hash(self.project(ctx))
            fired = list(dict.fromkeys(self._predicate(ctx, settings, deadline)))
            if time.monotonic() > deadline:
                raise TimeoutError("gate deadline exceeded")
            return HardGateResult(
                rule_id=self.rule_id,
                rule_version=self.version,
                severity=self.severity,
                passed=not fired,
                decisive_conditions=tuple(fired),
                reason_codes=tuple(dict.fromkeys(self._CODES[f] for f in fired)),
                inputs_hash=h,
                config_version=cfg_v,
                evaluated_at=ctx.now,
                duration_ms=_elapsed_ms(t0),
            )
        except Exception as exc:  # INV-HG-4: fail-closed, never PASS by exception
            return _error_result(
                rule_id=self.rule_id,
                version=self.version,
                extra_codes=self._ERROR_CODES,
                inputs_hash_value=self._safe_hash(ctx, exc),
                cfg_v=cfg_v,
                evaluated_at=ctx.now,
                t0=t0,
                exc=exc,
            )

    def _safe_hash(self, ctx: GateContext, exc: BaseException) -> str:
        """Hash of the projection if it can be computed, else of a value-free marker."""
        try:
            return inputs_hash(self.project(ctx))
        except Exception:
            return inputs_hash({"rule_id": self.rule_id, "projection_error": type(exc).__name__})


def _elapsed_ms(t0: float) -> float:
    return max(0.0, (time.monotonic() - t0) * 1000.0)


def _error_text(exc: BaseException) -> str:
    """Value-free error text: the exception type only (CR-013 §7 TS review focus)."""
    if isinstance(exc, TimeoutError):
        return "TimeoutError: gate deadline exceeded"
    return type(exc).__name__


def _error_result(
    *,
    rule_id: str,
    version: str,
    extra_codes: Iterable[str],
    inputs_hash_value: str,
    cfg_v: str,
    evaluated_at: datetime,
    t0: float,
    exc: BaseException,
) -> HardGateResult:
    return HardGateResult(
        rule_id=rule_id,
        rule_version=version,
        severity="CRITICAL",
        passed=False,
        decisive_conditions=("evaluation_error",),
        reason_codes=tuple(dict.fromkeys((_EVALUATION_ERROR, *extra_codes))),
        inputs_hash=inputs_hash_value,
        config_version=cfg_v,
        evaluated_at=evaluated_at,
        duration_ms=_elapsed_ms(t0),
        error=_error_text(exc),
    )


# ── HG-01 mandatory policy (CR-013 §5.3) ────────────────────────────────────


class HG01MandatoryPolicy(_BaseGate):
    """FAIL when the governing policy is missing, not in force, unresolved or violated.

    The policy is resolved by the CALLER by governance scope — a GOVERNED_BY
    walk from the scoped node or a scope-glob rule match — **never by text or
    embedding similarity** (adversarial case C04). This gate never reads policy
    text, so a lexically dissimilar policy resolved by scope still counts.
    """

    rule_id = "HG-01"
    severity = "CRITICAL"
    _CODES = {
        "policy_missing": "DAG-HG01-POLICY_MISSING",
        "policy_expired": "DAG-HG01-POLICY_EXPIRED",
        "policy_not_yet_valid": "DAG-HG01-POLICY_EXPIRED",
        "policy_unresolved": "DAG-HG01-POLICY_UNRESOLVED",
        "policy_violated": "DAG-HG01-POLICY_VIOLATED",
    }

    def project(self, ctx: GateContext) -> dict[str, Any]:
        p = ctx.policy
        return {
            "scope": ctx.governance_scope,
            "now": ctx.now.isoformat(),
            "policy_id": p.policy_id if p else None,
            "valid_from": p.valid_from.isoformat() if p and p.valid_from else None,
            "valid_until": p.valid_until.isoformat() if p and p.valid_until else None,
            "open_contradictions": sorted_ids(p.open_contradiction_ids) if p else [],
            "violations": sorted_ids(ctx.policy_violations),
        }

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        p = ctx.policy
        if p is None:
            return ["policy_missing"]
        fired: list[str] = []
        if p.valid_until is not None and p.valid_until < ctx.now:
            fired.append("policy_expired")
        if p.valid_from is not None and p.valid_from > ctx.now:
            fired.append("policy_not_yet_valid")
        if p.open_contradiction_ids:
            fired.append("policy_unresolved")
        if ctx.policy_violations:
            fired.append("policy_violated")
        return fired


# ── HG-02 invalidated evidence (CR-013 §5.4) ────────────────────────────────


class HG02InvalidatedEvidence(_BaseGate):
    """FAIL when a dependency is invalidated and has not been recomputed.

    A node is invalid when the CR-017 ``dirty`` flag is set, or (pre-CR-017,
    ``dirty is None``) when its ``status`` is ``INVALIDATED``. ``recomputed``
    must be exactly ``True`` to clear it: ``None`` (unknown) is treated as
    incomplete. Severity is FAIL (resolvable, REPLAN-eligible) per the OQ-4
    ruling of 2026-09-13.
    """

    rule_id = "HG-02"
    severity = "FAIL"
    _CODES = {
        "evidence_invalidated": "DAG-HG02-EVIDENCE_INVALIDATED",
        "recompute_incomplete": "DAG-HG02-RECOMPUTE_INCOMPLETE",
    }

    def project(self, ctx: GateContext) -> dict[str, Any]:
        return {
            "deps": sorted_records(
                [n.node_id, n.status, n.dirty, n.recomputed] for n in ctx.dependency_nodes
            )
        }

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        fired: list[str] = []
        for n in ctx.dependency_nodes:
            invalid = n.dirty is True or n.status == "INVALIDATED"
            if invalid and n.recomputed is not True:
                fired.append(
                    "evidence_invalidated" if n.recomputed is None else "recompute_incomplete"
                )
        return sorted(set(fired))


# ── HG-03 provenance for high impact (CR-013 §5.4) ──────────────────────────


class HG03ProvenanceForHighImpact(_BaseGate):
    """FAIL when an action at or above the impact-tier minimum has no provenance.

    Provenance is counted over DISTINCT source identities, so duplicating one
    source never satisfies the gate (P-CORR, P-DUP). The tier minimum is not
    projected: ``config_version`` already commits to it.
    """

    rule_id = "HG-03"
    severity = "CRITICAL"
    _CODES = {"provenance_missing": "DAG-HG03-PROVENANCE_MISSING"}

    def project(self, ctx: GateContext) -> dict[str, Any]:
        return {
            "risk": (ctx.risk_level or "").strip().upper(),
            "prov_events": sorted_ids(ctx.provenance_event_ids),
            "prov_sources": sorted_ids(ctx.provenance_source_ids),
        }

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        risk = _RISK_ORDER.get((ctx.risk_level or "").strip().upper(), _RISK_ORDER["CRITICAL"])
        if risk < _RISK_ORDER[settings.hg03_impact_tier_min]:
            return []
        if not set(ctx.provenance_event_ids) or not set(ctx.provenance_source_ids):
            return ["provenance_missing"]
        return []


# ── HG-04 argument binding (CR-013 §5.5) ────────────────────────────────────


class HG04ArgsBinding(_BaseGate):
    """FAIL unless the executed arguments match the hash approved at grant time.

    Fail-closed: an absent approved or actual hash is ``BINDING_ABSENT`` (no
    default hash is ever substituted); both algorithms must equal
    ``settings.args_hash_algo``; the hashes are compared in constant time.
    Only hashes are projected, never raw arguments.
    """

    rule_id = "HG-04"
    severity = "CRITICAL"
    _CODES = {
        "binding_absent": "DAG-HG04-BINDING_ABSENT",
        "algo_mismatch": "DAG-HG04-ARGS_HASH_ALGO_MISMATCH",
        "hash_mismatch": "DAG-HG04-ARGS_HASH_MISMATCH",
    }

    def project(self, ctx: GateContext) -> dict[str, Any]:
        return {
            "approved": ctx.approved_args_hash,
            "approved_algo": ctx.approved_args_algo,
            "actual": ctx.actual_args_hash,
            "actual_algo": ctx.actual_args_algo,
        }

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        if ctx.approved_args_hash is None or ctx.actual_args_hash is None:
            return ["binding_absent"]
        if (
            ctx.approved_args_algo != ctx.actual_args_algo
            or ctx.actual_args_algo != settings.args_hash_algo
        ):
            return ["algo_mismatch"]
        if not hmac.compare_digest(
            ctx.approved_args_hash.encode("utf-8"), ctx.actual_args_hash.encode("utf-8")
        ):
            return ["hash_mismatch"]
        return []


# ── HG-05 poisoning (CR-013 §5.5) ───────────────────────────────────────────


class HG05Poisoning(_BaseGate):
    """FAIL when poisoning severity is at or above the threshold (≥), or unknown."""

    rule_id = "HG-05"
    severity = "CRITICAL"
    _CODES = {
        "severity_unknown": "DAG-HG05-POISONING_DETECTED",
        "poisoning_detected": "DAG-HG05-POISONING_DETECTED",
    }

    def project(self, ctx: GateContext) -> dict[str, Any]:
        return {"severity": ctx.poisoning_severity}

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        if ctx.poisoning_severity is None:
            return ["severity_unknown"]
        threshold = settings.hg05_poisoning_threshold
        if threshold is None:  # unreachable via HardGateRegistry; raise ⇒ fail closed
            raise ConfigurationError("hg05_poisoning_threshold is required")
        if ctx.poisoning_severity >= threshold:
            return ["poisoning_detected"]
        return []


# ── HG-06 actor authorisation — RBAC contract (CR-013 §5.6) ─────────────────


class HG06ActorAuthorized(_BaseGate):
    """FAIL unless RBAC confirms the actor may approve the required tier in time.

    ``core/rbac.py`` is a stdlib leaf with no timeout and stays untouched; the
    call is wrapped here with a hard deadline (``rbac_timeout_ms``). Deliberate
    divergence from the legacy governance gate, which allows approval when the
    RBAC module cannot be imported: under DAG an ``ImportError``, any exception
    or a timeout is a FAIL (``RBAC_UNAVAILABLE``). Results are never cached.
    """

    rule_id = "HG-06"
    severity = "CRITICAL"
    _CODES = {
        "actor_unauthorized": "DAG-HG06-ACTOR_UNAUTHORIZED",
        "rbac_unavailable": "DAG-HG06-RBAC_UNAVAILABLE",
        "actor_or_tier_missing": "DAG-HG06-RBAC_UNAVAILABLE",
    }
    _ERROR_CODES = ("DAG-HG06-RBAC_UNAVAILABLE",)

    def project(self, ctx: GateContext) -> dict[str, Any]:
        return {"actor": ctx.actor_id, "tier": ctx.required_tier}

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        if not ctx.actor_id or ctx.required_tier not in _VALID_TIERS:
            return ["actor_or_tier_missing"]
        outcome = _rbac_with_deadline(ctx.actor_id, ctx.required_tier, settings.rbac_timeout_ms)
        return [] if outcome == "ok" else [outcome]


def _rbac_with_deadline(actor_id: str, tier: str, timeout_ms: int) -> str:
    """Call ``graqle.core.rbac.check_approval`` under a hard deadline.

    Returns ``"ok"`` only when ``check_approval`` returned ``(True, ...)``.
    Timeout, ``ImportError`` or ANY exception ⇒ ``"rbac_unavailable"``;
    a ``False`` answer ⇒ ``"actor_unauthorized"``. Never retries.

    The call runs on a daemon thread joined with a timeout, so a hung RBAC
    backend can neither block this evaluation past its deadline nor block
    interpreter shutdown (a ``ThreadPoolExecutor`` context manager would wait
    for the hung call on exit).
    """
    try:
        from graqle.core.rbac import check_approval
    except ImportError:
        return "rbac_unavailable"

    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["result"] = check_approval(actor_id, tier)
        except BaseException as exc:  # recorded, never re-raised on the worker
            box["error"] = exc

    worker = threading.Thread(target=_call, name="dag-hg06-rbac", daemon=True)
    worker.start()
    worker.join(timeout_ms / 1000.0)
    if worker.is_alive() or "error" in box or "result" not in box:
        return "rbac_unavailable"
    result = box["result"]
    ok = result[0] if isinstance(result, tuple) and result else None
    return "ok" if ok is True else "actor_unauthorized"


# ── HG-07 material contradiction (CR-013 §5.7) ──────────────────────────────


class HG07MaterialContradiction(_BaseGate):
    """FAIL when a material contradiction has no co-existence ruling.

    Records are grouped by unordered pair, so listing a pair twice (or as
    (b, a)) counts once (P-CORR, adversarial case C12). Within a pair the
    decision is order-independent and fail-closed: the pair is resolved only if
    EVERY record of it carries a ``coexists_rule_id``, and its materiality is
    the maximum over its records, with unknown materiality treated as fully
    material.
    """

    rule_id = "HG-07"
    severity = "CRITICAL"
    _CODES = {"contradiction_unresolved": "DAG-HG07-CONTRADICTION_UNRESOLVED"}

    def project(self, ctx: GateContext) -> dict[str, Any]:
        return {
            "pairs": sorted_records(
                [
                    sorted([c.a_id, c.b_id]),
                    sorted_ids(c.source_ids),
                    c.materiality,
                    c.coexists_rule_id,
                ]
                for c in ctx.contradictions
            )
        }

    def _predicate(self, ctx: GateContext, settings: DagSettings, deadline: float) -> list[str]:
        threshold = settings.hg07_materiality_threshold
        if threshold is None:  # unreachable via HardGateRegistry; raise ⇒ fail closed
            raise ConfigurationError("hg07_materiality_threshold is required")
        pairs: dict[tuple[str, str], tuple[float, bool]] = {}
        for c in ctx.contradictions:
            a, b = sorted((c.a_id, c.b_id))
            m = 1.0 if c.materiality is None else c.materiality
            resolved = bool(c.coexists_rule_id)
            prev = pairs.get((a, b))
            if prev is not None:
                m, resolved = max(m, prev[0]), resolved and prev[1]
            pairs[(a, b)] = (m, resolved)
        for materiality, resolved in pairs.values():
            if not resolved and materiality >= threshold:
                return ["contradiction_unresolved"]
        return []


# ── registry and ordered evaluation (CR-013 §5.8) ───────────────────────────

#: Settings every live gate needs; absent ⇒ the evaluation is refused.
_REQUIRED_GATE_SETTINGS: tuple[str, ...] = (
    "hg05_poisoning_threshold",
    "hg07_materiality_threshold",
)


class HardGateRegistry:
    """The ordered, complete set of hard gates."""

    def __init__(self, gates: Iterable[HardGate]) -> None:
        by_id: dict[str, HardGate] = {}
        for gate in gates:
            if gate.rule_id in by_id:
                raise ConfigurationError(f"HardGateRegistry duplicate gate: {gate.rule_id}")
            by_id[gate.rule_id] = gate
        missing = [r for r in GATE_ORDER if r not in by_id]
        unknown = sorted(set(by_id) - set(GATE_ORDER))
        if missing or unknown:
            raise ConfigurationError(
                f"HardGateRegistry incomplete or unknown gates: missing={missing} unknown={unknown}"
            )
        self._gates: tuple[HardGate, ...] = tuple(by_id[r] for r in GATE_ORDER)

    @property
    def gates(self) -> tuple[HardGate, ...]:
        return self._gates

    def evaluate_all(self, ctx: GateContext, settings: DagSettings) -> tuple[HardGateResult, ...]:
        """Evaluate EVERY gate in G order — no short-circuit (INV-HG-2).

        Raises :class:`ConfigurationError` before any gate runs when a
        required setting is absent or the configuration cannot be
        fingerprinted. A gate that raises despite its own wrapper is recorded
        as a FAIL here; the other gates still run (P-EXC).
        """
        absent = [f for f in _REQUIRED_GATE_SETTINGS if getattr(settings, f) is None]
        if absent:
            raise ConfigurationError(f"DAG hard gates require settings: {absent}")
        cfg_v = config_version(settings)
        results: list[HardGateResult] = []
        for gate in self._gates:
            t0 = time.monotonic()
            try:
                results.append(gate.evaluate(ctx, settings))
            except ConfigurationError:
                raise
            except Exception as exc:
                results.append(
                    _error_result(
                        rule_id=gate.rule_id,
                        version=getattr(gate, "version", "unknown"),
                        extra_codes=(),
                        inputs_hash_value=inputs_hash(
                            {"rule_id": gate.rule_id, "projection_error": type(exc).__name__}
                        ),
                        cfg_v=cfg_v,
                        evaluated_at=ctx.now,
                        t0=t0,
                        exc=exc,
                    )
                )
        return tuple(results)


def all_passed(results: Iterable[HardGateResult]) -> bool:
    return all(r.passed for r in results)


def decisive_rule(results: Iterable[HardGateResult]) -> str | None:
    """The first failed gate in G order, or ``None`` when all passed."""
    for r in results:
        if not r.passed:
            return r.rule_id
    return None


def default_registry() -> HardGateRegistry:
    gates: tuple[Callable[[], HardGate], ...] = (
        HG01MandatoryPolicy,
        HG02InvalidatedEvidence,
        HG03ProvenanceForHighImpact,
        HG04ArgsBinding,
        HG05Poisoning,
        HG06ActorAuthorized,
        HG07MaterialContradiction,
    )
    return HardGateRegistry(g() for g in gates)
