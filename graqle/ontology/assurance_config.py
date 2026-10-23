"""DAG-2026 assurance ontology configuration (CR-016 §3.3, PR-016b).

:class:`AssuranceOntologyConfig` is built only when ``GRAQLE_DAG_ENABLED`` is on,
by :func:`load_assurance_ontology_config`, and it has NO defaults for the values
that shape the data: the scope-key fields (private), the merge priority,
the label ceiling and the migration batch size. Anything absent or unresolvable
is a ``ConfigurationError`` naming the setting, never a value.

The scope-key fields and merge priority live in the private file's ``refs:``
section; ``GRAQLE_DAG_SCOPE_KEY_FIELDS_REF`` and ``GRAQLE_DAG_MERGE_PRIORITY_REF``
name the entries. ``GRAQLE_DAG_MERGE_PRIORITY_REF=sdk_default`` selects the
SDK's built-in merge priority.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.ontology.assurance_config
# risk: LOW (impact radius: 0 existing callers -- PR-016b migration, CR-017 scope keys)
# dependencies: pydantic, graqle.assurance.settings (lazy)
# constraints: no defaults for private or data-shaping values; flag off => refuses
# -- /graqle:intelligence --
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["SDK_DEFAULT_PRIORITY", "AssuranceOntologyConfig", "load_assurance_ontology_config"]

#: ``GRAQLE_DAG_MERGE_PRIORITY_REF`` value that selects the SDK's own ordering.
SDK_DEFAULT_PRIORITY = "sdk_default"


def _names(value: Any, what: str) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{what} must be a list of field names")
    out = tuple(value)
    if (
        not out
        or not all(isinstance(v, str) and v.strip() for v in out)
        or len(set(out)) != len(out)
    ):
        raise ValueError(f"{what} must be non-empty, distinct, non-blank names")
    return out


class AssuranceOntologyConfig(BaseModel):
    """Resolved assurance configuration. Frozen; unknown fields rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    secondary_labels_enabled: bool
    label_safe_node_ceiling: int = Field(gt=0)
    migration_batch_size: int = Field(gt=0)
    #: Private. Kept out of repr so it never lands in a log line.
    scope_key_fields: tuple[str, ...] = Field(repr=False)
    #: ``None`` means the SDK default ordering.
    merge_priority: tuple[str, ...] | None = Field(default=None, repr=False)

    @field_validator("scope_key_fields", mode="before")
    @classmethod
    def _scope_fields(cls, v: Any) -> tuple[str, ...]:
        return _names(v, "scope_key_fields")

    @field_validator("merge_priority", mode="before")
    @classmethod
    def _priority(cls, v: Any) -> tuple[str, ...] | None:
        return None if v is None else _names(v, "merge_priority")


def load_assurance_ontology_config(settings: Any = None) -> AssuranceOntologyConfig:
    """Build the config from DAG settings and the private ``refs:`` section.

    Raises ``ConfigurationError`` when the flag is off, when a required setting
    is absent, or when a ref does not resolve to a valid list.
    """
    from graqle.assurance.settings import (  # lazy: zero cost with the flag off
        ConfigurationError,
        env_name,
        is_dag_enabled,
        load_dag_settings,
        resolve_private_ref,
    )

    if not is_dag_enabled():
        raise ConfigurationError(
            "the assurance ontology configuration needs GRAQLE_DAG_ENABLED=true"
        )
    s = settings if settings is not None else load_dag_settings()
    missing = [
        f
        for f in (
            "scope_key_fields_ref",
            "merge_priority_ref",
            "assurance_label_ceiling",
            "assurance_migration_batch",
        )
        if getattr(s, f) in (None, "")
    ]
    if missing:
        raise ConfigurationError(
            "assurance ontology settings are absent: " + ", ".join(env_name(m) for m in missing)
        )
    fields = resolve_private_ref(s.scope_key_fields_ref)
    priority = None
    if s.merge_priority_ref != SDK_DEFAULT_PRIORITY:
        priority = resolve_private_ref(s.merge_priority_ref)
    try:
        return AssuranceOntologyConfig(
            secondary_labels_enabled=s.assurance_secondary_labels,
            label_safe_node_ceiling=s.assurance_label_ceiling,
            migration_batch_size=s.assurance_migration_batch,
            scope_key_fields=fields,
            merge_priority=priority,
        )
    except ValueError as exc:
        # Names only; the pydantic error would carry the private values.
        locs = sorted({str(e["loc"][0]) for e in getattr(exc, "errors", lambda: [])()} or {"value"})
        raise ConfigurationError("assurance ontology config invalid: " + ", ".join(locs)) from None
