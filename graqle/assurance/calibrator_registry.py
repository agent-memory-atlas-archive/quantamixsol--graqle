"""Versioned calibrators per (dimension, class, domain) -- strict, JSON-only.

The registry is the DAG's own calibrator store. It differs from the scalar
calibration factory on purpose:

* persistence is JSON only; a pickle (or any non-JSON) file in the registry
  directory is a :class:`ConfigurationError`, never loaded;
* an unknown method or a record whose version does not match its content raises
  ``DAG-CV-006-CALIBRATOR_VERSION_UNKNOWN``; there is no silent fallback to a
  default calibrator;
* every calibrated value is finite and inside the unit interval, or the call
  raises.

Staleness (time-to-live) is evaluated with an injected clock so tests need no
sleeping. The divergence guard lives in ``ConfidenceVectorBuilder``; this module
supplies the record and the strict ``apply``.
"""

from __future__ import annotations

# -- graqle:intelligence --
# module: graqle.assurance.calibrator_registry
# risk: LOW (impact radius: 0 modules -- new file)
# dependencies: graqle.assurance.confidence_vector, graqle.calibration.methods
# constraints: JSON only; no pickle; no fallback calibrator; fail closed
# -- /graqle:intelligence --
import hashlib
import json
import math
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import numpy as np
from pydantic import BaseModel, ConfigDict, ValidationError

from graqle.assurance.confidence_vector import DimensionName, EntityClass
from graqle.config.exceptions import ConfigurationError

__all__ = [
    "CODE_VERSION_UNKNOWN",
    "CalibratorKey",
    "CalibratorRecord",
    "CalibratorRegistry",
]

CODE_VERSION_UNKNOWN = "DAG-CV-006-CALIBRATOR_VERSION_UNKNOWN"

_VERSION_CHARS = 16
_FILE_SUFFIX = ".json"
_EPS = 1e-7


class CalibratorKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dimension: DimensionName
    entity_class: EntityClass
    domain: str


class CalibratorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: CalibratorKey
    method: Literal["temperature", "platt", "isotonic_json"]
    params: dict[str, float | list[float]]
    calibrator_version: str
    fitted_at_unix: float
    n_samples: int
    dataset_hash: str
    ece_at_fit: float
    config_version: str


def _canon(payload: dict[str, Any]) -> bytes:
    from graqle.governance.tamper_evidence.canonicalize import canon  # lazy

    return canon(payload)


def _version_of(
    key: CalibratorKey,
    method: str,
    params: dict[str, Any],
    fitted_at_unix: float,
    dataset_hash: str,
) -> str:
    body = {
        "key": key.model_dump(mode="json"),
        "method": method,
        "params": params,
        "fitted_at_unix": fitted_at_unix,
        "dataset_hash": dataset_hash,
    }
    return hashlib.sha256(_canon(body)).hexdigest()[:_VERSION_CHARS]


def _finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _validate_params(rec: CalibratorRecord) -> None:
    """Strict parameter check; any defect raises (fail closed)."""
    p = rec.params
    if rec.method == "temperature":
        t = p.get("temperature")
        if set(p) != {"temperature"} or not _finite(t) or t <= 0:  # type: ignore[operator]
            raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: invalid temperature parameters")
        return
    if rec.method == "platt":
        a, b = p.get("a"), p.get("b")
        # a > 0 keeps the map monotone non-decreasing.
        if set(p) != {"a", "b"} or not _finite(a) or not _finite(b) or a <= 0:  # type: ignore[operator]
            raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: invalid platt parameters")
        return
    xs, ys = p.get("x"), p.get("y")
    if (
        set(p) != {"x", "y"}
        or not isinstance(xs, list)
        or not isinstance(ys, list)
        or len(xs) != len(ys)
        or len(xs) < 2
        or not all(_finite(v) for v in (*xs, *ys))
    ):
        raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: invalid isotonic knots")
    if any(b <= a for a, b in zip(xs, xs[1:])) or any(b < a for a, b in zip(ys, ys[1:])):
        raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: isotonic knots must be monotone")
    if any(v < 0.0 or v > 1.0 for v in ys):
        raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: isotonic knot values leave the unit interval")


def _logit(p: float) -> float:
    q = min(max(p, _EPS), 1.0 - _EPS)
    return math.log(q / (1.0 - q))


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def _filename(key: CalibratorKey) -> str:
    tag = hashlib.sha256(key.domain.encode("utf-8")).hexdigest()[:_VERSION_CHARS]
    return f"{key.dimension.value}__{key.entity_class.value}__{tag}{_FILE_SUFFIX}"


def _export_params(calibrator: Any) -> tuple[str, dict[str, Any]]:
    """Extract JSON-safe parameters from a fitted calibrator (never pickles)."""
    from graqle.calibration.methods import (
        IsotonicCalibration,
        PlattScaling,
        TemperatureScaling,
    )

    if not getattr(calibrator, "fitted", False):
        raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: calibrator is not fitted")
    if isinstance(calibrator, TemperatureScaling):
        return "temperature", {"temperature": float(calibrator.temperature)}
    if isinstance(calibrator, PlattScaling):
        return "platt", {"a": float(calibrator._a), "b": float(calibrator._b)}
    if isinstance(calibrator, IsotonicCalibration):
        model = calibrator._model
        xs = getattr(model, "X_thresholds_", None)
        ys = getattr(model, "y_thresholds_", None)
        if xs is None or ys is None:
            raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: isotonic model has no knots")
        return "isotonic_json", {
            "x": [float(v) for v in np.asarray(xs)],
            "y": [float(v) for v in np.asarray(ys)],
        }
    raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: unsupported calibrator type")


class CalibratorRegistry:
    """Strict calibrator store backed by a directory of JSON files."""

    def __init__(self, path: Path, clock: Callable[[], float]) -> None:
        self._path = Path(path)
        self._clock = clock
        self._recs: dict[CalibratorKey, CalibratorRecord] = self._load_all()

    # -- loading ---------------------------------------------------------

    def _load_all(self) -> dict[CalibratorKey, CalibratorRecord]:
        if not self._path.is_dir():
            raise ConfigurationError("calibrator registry path is not a directory")
        recs: dict[CalibratorKey, CalibratorRecord] = {}
        for entry in sorted(self._path.iterdir()):
            if entry.name.startswith(".") and not entry.is_file():
                continue
            if entry.suffix != _FILE_SUFFIX or not entry.is_file():
                # pickle or any other format is refused outright, unread.
                raise ConfigurationError(
                    f"calibrator registry accepts JSON files only; found {entry.name!r}"
                )
            rec = self._read_one(entry)
            if rec.key in recs:
                raise ConfigurationError("calibrator registry holds duplicate keys")
            recs[rec.key] = rec
        return recs

    @staticmethod
    def _read_one(entry: Path) -> CalibratorRecord:
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
            rec = CalibratorRecord.model_validate(data)
        except (OSError, ValueError, ValidationError) as exc:
            raise ConfigurationError(
                f"{CODE_VERSION_UNKNOWN}: unreadable calibrator record "
                f"{entry.name!r} ({type(exc).__name__})"
            ) from None
        _validate_params(rec)
        expected = _version_of(
            rec.key, rec.method, rec.params, rec.fitted_at_unix, rec.dataset_hash
        )
        if rec.calibrator_version != expected or entry.name != _filename(rec.key):
            raise ConfigurationError(
                f"{CODE_VERSION_UNKNOWN}: record {entry.name!r} does not match its version"
            )
        return rec

    # -- access ----------------------------------------------------------

    def lookup(
        self, dimension: DimensionName, entity_class: EntityClass, domain: str
    ) -> CalibratorRecord | None:
        return self._recs.get(
            CalibratorKey(dimension=dimension, entity_class=entity_class, domain=domain)
        )

    def is_stale(self, rec: CalibratorRecord, ttl_seconds: int) -> bool:
        """Older than the time-to-live, or stamped in the future, is stale."""
        age = self._clock() - rec.fitted_at_unix
        return age < 0 or age > ttl_seconds

    def apply(self, rec: CalibratorRecord, raw: float) -> float:
        """Calibrate ``raw`` with a registered record; raises on any mismatch."""
        held = self._recs.get(rec.key)
        if held is None or held.calibrator_version != rec.calibrator_version:
            raise ConfigurationError(f"{CODE_VERSION_UNKNOWN}: record is not registered")
        if not _finite(raw) or raw < 0.0 or raw > 1.0:
            raise ConfigurationError("raw value must be finite and inside the unit interval")
        p = held.params
        if held.method == "temperature":
            out = _sigmoid(_logit(raw) / p["temperature"])  # type: ignore[operator]
        elif held.method == "platt":
            out = _sigmoid(p["a"] * _logit(raw) + p["b"])  # type: ignore[operator]
        elif held.method == "isotonic_json":
            out = float(np.interp(raw, p["x"], p["y"]))
        else:  # pragma: no cover - the Literal type makes this unreachable
            raise ConfigurationError(CODE_VERSION_UNKNOWN)
        if not math.isfinite(out):
            raise ConfigurationError("calibrated value is not finite")
        return min(max(float(out), 0.0), 1.0)

    # -- registration ----------------------------------------------------

    def register(
        self,
        key: CalibratorKey,
        calibrator: Any,
        n_samples: int,
        dataset_hash: str,
        ece_at_fit: float,
        config_version: str,
    ) -> CalibratorRecord:
        method, params = _export_params(calibrator)
        fitted_at = float(self._clock())
        rec = CalibratorRecord(
            key=key,
            method=method,  # type: ignore[arg-type]
            params=params,
            calibrator_version=_version_of(key, method, params, fitted_at, dataset_hash),
            fitted_at_unix=fitted_at,
            n_samples=n_samples,
            dataset_hash=dataset_hash,
            ece_at_fit=ece_at_fit,
            config_version=config_version,
        )
        _validate_params(rec)
        self._write_json(rec)
        self._recs[key] = rec
        return rec

    def _write_json(self, rec: CalibratorRecord) -> None:
        target = self._path / _filename(rec.key)
        fd, tmp = tempfile.mkstemp(dir=self._path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(rec.model_dump(mode="json"), fh, sort_keys=True, allow_nan=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
