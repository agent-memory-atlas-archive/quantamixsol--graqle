"""CR-013 AC-13 — field-name parity with the CR-017 and CR-018 models.

The CR-017 / CR-018 models are not in the tree yet; until they land the
parity checks are xfail(strict) so their arrival forces this file to be
updated. The local interface is asserted unconditionally.
"""

from __future__ import annotations

import importlib

import pytest

from graqle.assurance.hard_gates import DependencyNodeRef, GateContext

CR017_FIELDS = {"node_id", "status", "dirty", "recomputed"}
CR018_FIELDS = {"approved_args_hash", "approved_args_algo", "actual_args_hash", "actual_args_algo"}


def test_local_interface_field_names() -> None:
    assert CR017_FIELDS <= set(DependencyNodeRef.model_fields)
    assert CR018_FIELDS <= set(GateContext.model_fields)


def _try_import(*names: str):  # type: ignore[no-untyped-def]
    for name in names:
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


@pytest.mark.xfail(strict=True, reason="CR-017 DependencyNodeRef not landed")
def test_cr017_parity() -> None:
    mod = _try_import("graqle.assurance.invalidation", "graqle.assurance.dependency")
    assert mod is not None
    assert CR017_FIELDS <= set(mod.DependencyNodeRef.model_fields)


@pytest.mark.xfail(strict=True, reason="CR-018 approved_args_* model not landed")
def test_cr018_parity() -> None:
    mod = _try_import("graqle.assurance.args_binding", "graqle.assurance.grants")
    assert mod is not None
    models = [m for m in vars(mod).values() if hasattr(m, "model_fields")]
    assert any(CR018_FIELDS <= set(m.model_fields) for m in models)
