"""``graqle.assurance`` — DAG-2026 Decision Assurance Gate (foundation, CR-012).

Dependency direction: ``graqle.assurance`` → ``graqle.governance``, never the
reverse (CR-012 AC-21). With ``GRAQLE_DAG_ENABLED`` unset nothing in this
package changes SDK behaviour; ``GovernanceMiddleware.check()`` is untouched.

PR-012a exported the flag and settings surface. PR-012b adds ``GateOutcome``,
the closed reason-code registry and the ``GateVerdict`` schema; the
``DecisionAssuranceGate`` component itself arrives in CR-015.
"""

# ── graqle:intelligence ──
# module: graqle.assurance.__init__
# risk: LOW (impact radius: 0 modules — new package, no existing callers)
# dependencies: graqle.assurance.settings
# constraints: never imported by graqle.governance.*
# ── /graqle:intelligence ──

from graqle.assurance.outcomes import (
    OUTCOME_SEVERITY,
    GateOutcome,
    worst,
    worst_terminal,
)
from graqle.assurance.reason_codes import (
    REGISTRY,
    ReasonCode,
    Severity,
    max_severity,
    resolvable,
    validate,
)
from graqle.assurance.settings import (
    ConfigurationError,
    DagSettings,
    config_provenance,
    config_version,
    is_dag_enabled,
    load_dag_settings,
    reset_dag_settings_cache,
    validate_flag_consistency,
)
from graqle.assurance.verdict import (
    VERDICT_SCHEMA_VERSION,
    DeterminismRecord,
    GateVerdict,
    GateVerdictRef,
    HardGateResultRef,
)

__all__ = [
    # PR-012a — flag + settings
    "ConfigurationError",
    "DagSettings",
    "config_provenance",
    "config_version",
    "is_dag_enabled",
    "load_dag_settings",
    "reset_dag_settings_cache",
    "validate_flag_consistency",
    # PR-012b — outcomes
    "GateOutcome",
    "OUTCOME_SEVERITY",
    "worst",
    "worst_terminal",
    # PR-012b — reason codes
    "REGISTRY",
    "ReasonCode",
    "Severity",
    "max_severity",
    "resolvable",
    "validate",
    # PR-012b — verdict
    "VERDICT_SCHEMA_VERSION",
    "DeterminismRecord",
    "GateVerdict",
    "GateVerdictRef",
    "HardGateResultRef",
]
