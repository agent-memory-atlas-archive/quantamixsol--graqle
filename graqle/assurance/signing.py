"""Per-event ed25519 signing and key rotation (CR-018 PR-018b, spec 5.4).

The private key is loaded from ``GRAQLE_DAG_SIGNING_KEY_PATH`` (env-only) and
attached to an :class:`Ed25519KeyManifest` entry; the message signed is
domain-separated from SD-001 by its field set. Rotation RETIRES the old key
after the overlap window; it never revokes (revocation is for compromise).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.signing
# risk: MEDIUM (key material handling; new module, no consumers outside PR-018b)
# dependencies: cryptography, graqle.governance.custody.ed25519_key_manifest,
#   graqle.governance.tamper_evidence.canonicalize, graqle.assurance.provenance_event
# constraints: key path env-only; key file must not be group/world readable;
#   never logs key material
# -- /graqle:intelligence --
import logging
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from graqle.assurance._ids import SYSTEM_KEYS_TRAJECTORY, new_id, rfc3339, utcnow
from graqle.assurance.provenance_event import (
    SCHEMA_VERSION,
    Activity,
    Actor,
    ActorType,
    Assessment,
    EventType,
    IdentityAssurance,
    Inputs,
    _parse,
)
from graqle.assurance.provenance_settings import ProvenanceSettings
from graqle.config.exceptions import ConfigurationError
from graqle.governance.custody.ed25519_key_manifest import (
    Ed25519KeyManifest,
    KeyManifestError,
    KeyState,
)
from graqle.governance.tamper_evidence.canonicalize import canon

__all__ = ["DagSigner", "RotationPlan", "rotate", "retire_due"]

_log = logging.getLogger("graqle.assurance.signing")
_SECONDS_PER_DAY = 86400  # unit conversion, not a tuning value


def _age_days(since: datetime, now: datetime) -> float:
    return (now - since).total_seconds() / _SECONDS_PER_DAY


def _check_key_file(path: Path) -> None:
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigurationError("signing key file must not be group/world accessible")


class DagSigner:
    """Signs ``(canonical_hash, previous_event_hash, sequence_number)`` per event."""

    def __init__(
        self,
        cfg: ProvenanceSettings,
        manifest: Ed25519KeyManifest,
        clock: Callable[[], datetime] = utcnow,
        high_water: int = 0,
    ) -> None:
        if None in (cfg.signing_key_path, cfg.signing_key_id, cfg.signing_key_version):
            raise ConfigurationError(
                "GRAQLE_DAG_SIGNING_KEY_ID/_VERSION/_PATH are required when GRAQLE_DAG_ENABLED is set"
            )
        if int(cfg.signing_key_version or 0) < high_water:  # monotonic, like KeyState
            raise ConfigurationError(
                "GRAQLE_DAG_SIGNING_KEY_VERSION is lower than the manifest high-water mark"
            )
        path = Path(str(cfg.signing_key_path))
        try:
            _check_key_file(path)
            key = load_pem_private_key(path.read_bytes(), None)  # unencrypted PEM; 0600 file is the protection
        except ConfigurationError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise ConfigurationError(f"signing key could not be loaded ({type(exc).__name__})") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise ConfigurationError("signing key must be an ed25519 private key")
        self._bind(str(cfg.signing_key_id), int(cfg.signing_key_version or 0), key, cfg, manifest, clock)

    def _bind(
        self,
        kid: str,
        kver: int,
        key: Ed25519PrivateKey,
        cfg: ProvenanceSettings,
        manifest: Ed25519KeyManifest,
        clock: Callable[[], datetime],
    ) -> None:
        try:
            entry = manifest.get(kid)  # UnknownKidError -> ConfigurationError
        except KeyManifestError:
            raise ConfigurationError("configured kid is not in the key manifest") from None
        now = clock()
        if not entry.can_sign(now):
            raise ConfigurationError("configured kid is not ACTIVE / in-window")
        if _age_days(entry.valid_from, now) > cfg.key_max_age_days:
            raise ConfigurationError("kid exceeds GRAQLE_DAG_KEY_MAX_AGE_DAYS; rotate before enabling")
        try:
            manifest.attach_private_key(kid, key)
        except KeyManifestError:
            raise ConfigurationError("signing key does not match the manifest entry") from None
        self.kid, self.kver, self.manifest, self.clock = kid, kver, manifest, clock
        _log.info("dag.signer.active kid=%s key_version=%s valid_until=%s", kid, kver, entry.valid_until)

    @classmethod
    def for_registered_key(
        cls,
        cfg: ProvenanceSettings,
        manifest: Ed25519KeyManifest,
        kid: str,
        key_version: int,
        private_key: Ed25519PrivateKey,
        clock: Callable[[], datetime] = utcnow,
    ) -> DagSigner:
        """Signer for a key whose material is already in hand (rotation, tests)."""
        self = cls.__new__(cls)
        self._bind(kid, key_version, private_key, cfg, manifest, clock)
        return self

    def sign_event(
        self, canonical_hash: str, previous_event_hash: str, sequence_number: int, signed_at: str
    ) -> tuple[str, str, int]:
        msg = canon(
            {
                "schema_version": SCHEMA_VERSION,
                "canonical_hash": canonical_hash,
                "previous_event_hash": previous_event_hash,
                "sequence_number": sequence_number,
                "kid": self.kid,
                "signed_at": signed_at,
            }
        )
        sig = self.manifest.sign(self.kid, msg, at=_parse(signed_at))
        return sig.hex(), self.kid, self.kver


@dataclass(frozen=True)
class RotationPlan:
    """Old key ``kid`` is retired (never revoked) once ``retire_at`` has passed."""

    kid: str
    retire_at: datetime


def retire_due(
    manifest: Ed25519KeyManifest,
    plans: list[RotationPlan],
    clock: Callable[[], datetime] = utcnow,
) -> list[str]:
    """Retire every planned key whose overlap window has ended; return their kids."""
    now = clock()
    retired: list[str] = []
    for plan in plans:
        if now >= plan.retire_at and manifest.get(plan.kid).state is KeyState.ACTIVE:
            manifest.retire(plan.kid)
            retired.append(plan.kid)
    return retired


def rotate(
    cfg: ProvenanceSettings,
    manifest: Ed25519KeyManifest,
    recorder: Any,
    *,
    new_kid: str,
    new_private_key: Ed25519PrivateKey,
    config_version: str,
    clock: Callable[[], datetime] = utcnow,
) -> RotationPlan:
    """Register ``new_kid`` ACTIVE, schedule the old key's retirement, record ``key_rotated``.

    The ``key_rotated`` event is signed by the NEW key (proof of possession).
    """
    if cfg.signing_key_id is None or cfg.signing_key_version is None:
        raise ConfigurationError("rotation needs the current signing key id and version")
    # Whole seconds: event timestamps are second-resolution, so a window opening
    # mid-second would put the key_rotated event's signed_at before valid_from.
    now = clock().replace(microsecond=0)
    old = manifest.get(cfg.signing_key_id)
    manifest.register(
        new_kid,
        new_private_key.public_key(),
        valid_from=now,
        valid_until=now + timedelta(days=cfg.key_max_age_days),
        state=KeyState.ACTIVE,
        private_key=new_private_key,
    )
    next_version = cfg.signing_key_version + 1
    new_signer = DagSigner.for_registered_key(cfg, manifest, new_kid, next_version, new_private_key, clock)
    plan = RotationPlan(kid=old.kid, retire_at=now + timedelta(days=cfg.key_overlap_days))
    recorder.record(
        event_type=EventType.KEY_ROTATED,
        actor=Actor(
            agent_id="dag-signer",
            type=ActorType.SYSTEM,
            identity_assurance=IdentityAssurance.IAL2,
            kid=new_kid,
        ),
        activity=Activity(
            decision_id=new_id("dec"),
            trajectory_id=SYSTEM_KEYS_TRAJECTORY,
            checkpoint=0,
            model_version="n/a",
            rule_set_version="n/a",
            policy_bundle_version="n/a",
            config_version=config_version,
        ),
        inputs=Inputs(
            policy_refs=[f"kid:{old.kid}", f"kid:{new_kid}", f"key_version:{next_version}"]
        ),
        assessment=Assessment(reason_codes=["DAG-PV-KEY-ROTATED"]),
        occurred_at=rfc3339(now),
        signer=new_signer,
    )
    return plan
