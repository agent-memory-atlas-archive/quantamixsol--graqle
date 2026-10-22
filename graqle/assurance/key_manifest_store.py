"""Persistence for the signing-key manifest (CR-018 PR-018b, spec 3.3 / 5.4).

Only PUBLIC material is written: kid, raw public key, validity window, state
and the key version. Private keys never touch this file. The recorded key
versions give the manifest a high-water mark; a configured
``GRAQLE_DAG_SIGNING_KEY_VERSION`` below it is refused (fail closed).
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.key_manifest_store
# risk: MEDIUM (trust anchor file; new module, consumers are the signer wiring and `graq dag rotate-key`)
# dependencies: cryptography, graqle.governance.custody.ed25519_key_manifest, graqle.config.exceptions
# constraints: public material only; atomic replace; any parse problem raises ConfigurationError
# -- /graqle:intelligence --
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from graqle.config.exceptions import ConfigurationError
from graqle.governance.custody.ed25519_key_manifest import (
    Ed25519KeyManifest,
    KeyState,
)

__all__ = ["ManifestRecord", "load_manifest", "save_manifest"]

_FORMAT = "graqle.dag.key_manifest.v1"
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class ManifestRecord:
    """A loaded manifest plus the key version of each kid."""

    manifest: Ed25519KeyManifest
    versions: dict[str, int] = field(default_factory=dict)
    #: kid -> instant after which the dual-key overlap ends and it is retired.
    retire_at: dict[str, datetime] = field(default_factory=dict)

    @property
    def high_water(self) -> int:
        return max(self.versions.values(), default=0)


def save_manifest(
    path: str | os.PathLike[str],
    manifest: Ed25519KeyManifest,
    versions: dict[str, int],
    retire_at: dict[str, datetime] | None = None,
) -> None:
    """Atomically write the public manifest. Every kid needs a key version >= 1."""
    entries = []
    for kid in manifest.kids():
        version = versions.get(kid)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ConfigurationError("every manifest kid needs a key version of at least 1")
        entry = manifest.get(kid)
        entries.append(
            {
                "kid": kid,
                "key_version": version,
                "public_key": entry.public_key.public_bytes(*_RAW).hex(),
                "valid_from": entry.valid_from.isoformat(),
                "valid_until": entry.valid_until.isoformat(),
                "state": entry.state.value,
            }
        )
        if retire_at and kid in retire_at:
            entries[-1]["retire_at"] = retire_at[kid].isoformat()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".key_manifest.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"format": _FORMAT, "keys": entries}, fh, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load_manifest(path: str | os.PathLike[str]) -> ManifestRecord:
    """Read the manifest; a missing or malformed file raises ``ConfigurationError``."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        if doc.get("format") != _FORMAT:
            raise ValueError("format")
        manifest = Ed25519KeyManifest()
        versions: dict[str, int] = {}
        retire_at: dict[str, datetime] = {}
        for item in doc["keys"]:
            version = item["key_version"]
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise ValueError("key_version")
            manifest.register(
                item["kid"],
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(item["public_key"])),
                valid_from=datetime.fromisoformat(item["valid_from"]),
                valid_until=datetime.fromisoformat(item["valid_until"]),
                state=KeyState(item["state"]),
            )
            versions[item["kid"]] = version
            if "retire_at" in item:
                retire_at[item["kid"]] = datetime.fromisoformat(item["retire_at"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ConfigurationError(f"key manifest could not be loaded ({type(exc).__name__})") from None
    return ManifestRecord(manifest=manifest, versions=versions, retire_at=retire_at)
