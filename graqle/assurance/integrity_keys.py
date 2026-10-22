"""Integrity keyring from DAG settings (CR-016 PR-016b).

Lives in ``graqle.assurance`` because it reads :mod:`graqle.assurance.settings`;
the keyring type itself is in :mod:`graqle.ontology.assurance_integrity`, which
the governance write path imports without loading this package.
"""

from __future__ import annotations

from typing import Any

from graqle.assurance.settings import ConfigurationError, load_dag_settings
from graqle.ontology.assurance_integrity import IntegrityKeyring

__all__ = ["keyring_from_settings"]


def keyring_from_settings(settings: Any = None) -> IntegrityKeyring:
    """Keyring from ``GRAQLE_DAG_CONFIG_SALT``, plus the previous pair during an
    overlap window. Fails closed with ``ConfigurationError`` when no salt is set.
    """
    s = settings if settings is not None else load_dag_settings()
    salt = s.config_salt.get_secret_value() if s.config_salt is not None else ""
    if not salt.strip():
        raise ConfigurationError(
            "integrity digests need GRAQLE_DAG_CONFIG_SALT; none is configured"
        )
    previous = []
    if s.config_salt_previous is not None and s.assurance_hmac_version_previous:
        previous.append(
            (s.assurance_hmac_version_previous, s.config_salt_previous.get_secret_value())
        )
    return IntegrityKeyring.from_salts((s.assurance_hmac_version, salt), *previous)
