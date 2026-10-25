"""Packaged default runtime provider (CR-DAG-087-1 PR-B).

Imported lazily by ``adapter.ensure_runtime_registered`` only when ``GRAQLE_DAG_ENABLED`` is on.
It builds, once and at start-up, the baseline admission gate (rule DAG-RT-BASELINE-ADMIT) with
the seven hard gates, the signer and the file-backed provenance recorder. Anything missing or
unusable raises ``RuntimeNotRegisteredError`` naming ``register_runtime``: no silent degrade and
no per-call fallback.

In 0.87.1 the gate records every decision and admits only LOW-risk, zero-impact calls whose hard
gates all pass, at evidence tier BASELINE; everything else is REJECT or HOLD. Evidence-fed
scoring arrives in 0.88 (CR-DAG-088-1).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.default_provider
# risk: MEDIUM (start-up wiring on the flag-on path; flag-off never imports it)
# dependencies: graqle.assurance.{adapter,baseline,hard_gates,key_manifest_store,provenance_wiring,signing,settings}
# constraints: private values arrive from the environment only; no numeric tuning value here
# -- /graqle:intelligence --
from typing import Any

from graqle.assurance.adapter import RuntimeNotRegisteredError, RuntimeProvider
from graqle.assurance.baseline import BaselineAdmissionGate
from graqle.assurance.gate import EvaluationContext
from graqle.assurance.hard_gates import default_registry
from graqle.assurance.routing_settings import BaselineRoutingSettings
from graqle.config.exceptions import ConfigurationError

__all__ = ["build_default_provider"]

_SESSION_ID = "baseline"


def _build_gate() -> BaselineAdmissionGate:
    from graqle.assurance.key_manifest_store import load_manifest
    from graqle.assurance.provenance_wiring import build_recorder
    from graqle.assurance.settings import load_dag_settings
    from graqle.assurance.signing import DagSigner

    settings = load_dag_settings()
    cfg = settings.provenance
    if cfg is None:
        raise ConfigurationError("provenance settings are not available")
    record = load_manifest(cfg.key_manifest_path)
    signer = DagSigner(cfg, record.manifest, high_water=record.high_water)
    return BaselineAdmissionGate(
        registry=default_registry(),
        settings=settings,
        recorder=build_recorder(cfg, signer),
        routing=BaselineRoutingSettings.from_env(),
    )


def build_default_provider() -> RuntimeProvider:
    """Build the gate now (start-up) and return a provider that hands it out per call."""
    try:
        gate = _build_gate()
    except RuntimeNotRegisteredError:
        raise
    except Exception as exc:  # configuration, key, manifest or I/O problem: loud, at start-up
        raise RuntimeNotRegisteredError(
            f"the default DAG runtime provider could not be built ({type(exc).__name__}: {exc}); "
            "fix the GRAQLE_DAG_* settings or call "
            "graqle.assurance.adapter.register_runtime(provider)"
        ) from exc

    def provider(mw: Any, legacy: Any, **kwargs: Any) -> tuple[Any, EvaluationContext]:
        ctx = EvaluationContext(
            session_id=_SESSION_ID,
            actor_id=str(kwargs.get("actor", "") or ""),
            history=None,
            checkpoint=None,
            legacy_result=legacy,
        )
        return gate, ctx

    return provider
