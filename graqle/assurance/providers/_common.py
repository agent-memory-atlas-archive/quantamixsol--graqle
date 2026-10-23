"""Shared helpers for the CR-014 dimension providers."""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.providers._common
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance._hashing, graqle.assurance.confidence_vector
# constraints: never imported by graqle.governance.*
# -- /graqle:intelligence --

from collections.abc import Mapping
from typing import Any

from graqle.assurance._hashing import inputs_hash
from graqle.assurance.confidence_vector import (
    CODE_NOT_AVAILABLE,
    Availability,
    ProviderSignal,
    SignalSource,
)

__all__ = ["not_available", "signal_source"]


def signal_source(
    signal_id: str, source_module: str, payload: Mapping[str, Any], *, probabilistic: bool = False
) -> SignalSource:
    """A :class:`SignalSource` whose ``inputs_hash`` commits to ``payload``."""
    return SignalSource(
        signal_id=signal_id,
        source_module=source_module,
        inputs_hash=inputs_hash(dict(payload)),
        probabilistic=probabilistic,
    )


def not_available(*conditions: str) -> ProviderSignal:
    """Instrumentation absent: no value, never a default."""
    return ProviderSignal(
        availability=Availability.NOT_AVAILABLE,
        reason_codes=(CODE_NOT_AVAILABLE,),
        decisive_conditions=tuple(conditions),
    )
