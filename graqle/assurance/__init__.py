"""``graqle.assurance`` — DAG-2026 Decision Assurance Gate (foundation, CR-012).

Dependency direction: ``graqle.assurance`` → ``graqle.governance``, never the
reverse (CR-012 AC-21). With ``GRAQLE_DAG_ENABLED`` unset nothing in this
package changes SDK behaviour; ``GovernanceMiddleware.check()`` is untouched.

PR-012a exports the flag and settings surface only. ``GateOutcome``, the
reason-code registry and ``GateVerdict`` arrive in PR-012b; the
``DecisionAssuranceGate`` component itself arrives in CR-015.
"""

# ── graqle:intelligence ──
# module: graqle.assurance.__init__
# risk: LOW (impact radius: 0 modules — new package, no existing callers)
# dependencies: graqle.assurance.settings
# constraints: never imported by graqle.governance.*
# ── /graqle:intelligence ──

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

__all__ = [
    "ConfigurationError",
    "DagSettings",
    "config_provenance",
    "config_version",
    "is_dag_enabled",
    "load_dag_settings",
    "reset_dag_settings_cache",
    "validate_flag_consistency",
]
