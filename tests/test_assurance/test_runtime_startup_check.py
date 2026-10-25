"""CR-DAG-087-1 PR-A: registration hook and start-up self-check (acceptance 2 and 3).

Part delivered here: the hook and the loud start-up failure. The default provider and the
signed provenance are a separate PR (PR-B); the built-wheel test is PR-C.
"""

from __future__ import annotations

import pytest

from graqle.assurance import adapter
from graqle.core.governance import GovernanceConfig, GovernanceMiddleware


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    previous = adapter._runtime_provider
    adapter.register_runtime(None)
    GovernanceMiddleware._state_loaded = True
    yield
    adapter.register_runtime(previous)


def _provider(*_a: object, **_k: object):  # never called by these tests
    raise AssertionError("provider must not run at start-up")


def test_flag_on_without_provider_fails_at_startup_naming_register_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "_load_default_provider", lambda: None)
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    with pytest.raises(adapter.RuntimeNotRegisteredError, match="register_runtime"):
        GovernanceMiddleware(config=GovernanceConfig())


def test_flag_on_with_registered_provider_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter.register_runtime(_provider)
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    GovernanceMiddleware(config=GovernanceConfig())


def test_flag_on_registers_the_packaged_default_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_load_default_provider", lambda: _provider)
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")
    GovernanceMiddleware(config=GovernanceConfig())
    assert adapter._runtime_provider is _provider


def test_missing_default_module_means_none_shipped_but_other_import_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    def missing(name: str):
        raise ModuleNotFoundError("no module", name=name)

    monkeypatch.setattr(importlib, "import_module", missing)
    assert adapter._load_default_provider() is None

    def broken(name: str):
        raise ModuleNotFoundError("no dep", name="some_other_dependency")

    monkeypatch.setattr(importlib, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        adapter._load_default_provider()


def test_flag_off_never_runs_the_self_check(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> None:
        raise AssertionError("self-check must not run with the flag off")

    monkeypatch.setattr(adapter, "ensure_runtime_registered", boom)
    GovernanceMiddleware(config=GovernanceConfig())
