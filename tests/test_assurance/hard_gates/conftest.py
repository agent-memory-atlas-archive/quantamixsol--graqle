"""Fixtures for the CR-013 hard-gate tests (builders live in ``_builders``)."""

from __future__ import annotations

import pytest

from graqle.assurance.settings import DagSettings

from ._builders import make_settings


@pytest.fixture
def settings() -> DagSettings:
    return make_settings()


@pytest.fixture(autouse=True)
def _rbac_allows_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep HG-06 hermetic: a registered-approver stub unless a test overrides it."""
    import graqle.core.rbac as rbac

    monkeypatch.setattr(rbac, "check_approval", lambda actor_id, tier: (True, ""))
