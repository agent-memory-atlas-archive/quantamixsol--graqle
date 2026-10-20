"""Reasoning-quota wall (W3, ADR-245) — free monthly cap on graph reasoning.

Free tier gets a bounded number of ``graq run`` / ``graq reason`` invocations per
calendar month; paid tiers (Pro/Team/Enterprise) are unlimited. This is the
*reasoning-frequency* wall in the multi-wall lattice — independent of the node-cap
(size) wall, so a user who stays under the node cap still hits this if they reason a lot.

Design (consistent with ADR-245 + CR-LIC-03a/03b):
  - Tier comes from the VERIFIED licence (``manager.current_tier``), never a raw env/key
    presence — an unverified signal must never grant a paid entitlement (CR-LIC-03b rule).
  - Enforcement is ON BY DEFAULT; ``GRAQLE_ENFORCE_CAPS`` is an OPT-OUT only (shared with
    the node-cap wall). "User sets a flag to be enforced" would be a trivial bypass.
  - The count is per calendar month, persisted locally in ``.graqle/reasoning_quota.json``.
    Local enforcement is the offline bar (the standard freemium wall); a determined user
    can delete the file — server-side accounting is the un-bypassable upgrade (separate CR).
  - INTERNAL reasoning (e.g. a PR-Guardian scan that calls reason under the hood) is
    EXEMPT via ``internal=True`` so W2 and W3 never double-charge one user action.
  - Fail-open on any metering error: a quota-file hiccup must never break reasoning.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:  # POSIX advisory locking
    import fcntl
except ImportError:  # pragma: no cover — Windows
    fcntl = None  # type: ignore[assignment]

try:  # Windows mandatory locking
    import msvcrt
except ImportError:  # pragma: no cover — POSIX
    msvcrt = None  # type: ignore[assignment]

logger = logging.getLogger("graqle.licensing.reasoning_quota")

__all__ = [
    "FREE_REASONS_PER_MONTH",
    "QUOTA_FILENAME",
    "ReasoningQuotaExceeded",
    "ReasoningQuota",
    "quota_enforcement_enabled",
]

QUOTA_FILENAME = "reasoning_quota.json"
FREE_REASONS_PER_MONTH = 30  # generous enough to try; paid = unlimited
_SCHEMA_VERSION = 1

# Shared opt-out flag with the node-cap wall (ADR-245): enforcement is ON by default.
_ENFORCE_ENV = "GRAQLE_ENFORCE_CAPS"
_FALSY = frozenset({"0", "false", "no", "off", ""})

# CR-LIC-01 AC-3: user-level sibling record (relocatable ONLY under pytest).
_MARKER_FILENAME = "reasoning_quota_marker.json"
_USER_DIR_ENV = "GRAQLE_USER_DIR"


def _under_pytest() -> bool:
    from graqle.licensing.caps import under_pytest

    return under_pytest()


def _as_count(value: object) -> int:
    """Tolerant int: a corrupt entry reads as 0 rather than raising (the marker covers it)."""
    try:
        return max(int(value or 0), 0)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0


class ReasoningQuotaExceeded(Exception):
    """Raised when a FREE user exceeds the monthly reasoning quota."""

    def __init__(self, used: int, limit: int, month: str) -> None:
        super().__init__(
            f"reasoning quota reached: {used}/{limit} this month ({month})"
        )
        self.used = used
        self.limit = limit
        self.month = month


def quota_enforcement_enabled() -> bool:
    """True unless a *permitted* opt-out applies. Default ON.

    CR-LIC-01: ``GRAQLE_ENFORCE_CAPS=falsy`` is honoured only with a verified paid
    licence or under pytest; otherwise it is ignored (shared helper in ``caps``).
    """
    from graqle.licensing.caps import caps_enforced

    return caps_enforced()


def _paid_tier() -> bool:
    """True iff the VERIFIED licence is a paid tier (Pro/Team/Enterprise).

    Uses manager.current_tier (paid only from a signature+CRL+nonce-verified licence);
    never a raw env/key (CR-LIC-03b). Fail-safe: any error → treat as FREE (enforce).
    """
    try:
        from graqle.licensing.manager import LicenseTier, _get_manager

        return _get_manager().current_tier in (
            LicenseTier.PRO,
            LicenseTier.TEAM,
            LicenseTier.ENTERPRISE,
        )
    except Exception:  # noqa: BLE001
        return False


# Months of history to keep. One year plus the current month, so a year-on-year
# comparison still has data while the file stays bounded. Without pruning the JSON
# gains a key every month forever — slow, but unbounded, and nothing else trims it.
_RETAIN_MONTHS = 13


def _prune_old_months(data: dict, current: str) -> dict:
    """Drop month keys older than ``_RETAIN_MONTHS`` before ``current``.

    Non-month keys (``schema_version``) are preserved untouched, and anything that
    does not parse as ``YYYY-MM`` is left alone rather than silently discarded — a
    pruner that eats keys it does not understand is a data-loss bug waiting to happen.
    """
    try:
        cy, cm = (int(p) for p in current.split("-"))
    except (ValueError, AttributeError):
        return data
    cutoff = cy * 12 + cm - _RETAIN_MONTHS
    out = {}
    for key, value in data.items():
        try:
            y, m = (int(p) for p in str(key).split("-"))
        except ValueError:
            out[key] = value  # not a month key (e.g. schema_version) — keep
            continue
        if y * 12 + m > cutoff:
            out[key] = value
    return out


@dataclass
class QuotaReading:
    used: int
    limit: int          # -1 = unlimited (paid)
    month: str
    allowed: bool


class ReasoningQuota:
    """Per-month local reasoning-quota meter under a project's ``.graqle`` dir."""

    def __init__(self, graqle_dir: Path | str) -> None:
        self._path = Path(graqle_dir) / QUOTA_FILENAME

    def _load(self) -> dict:
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            logger.debug("reasoning quota file unreadable — treating as empty")
        return {}

    def _store(self, data: dict) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self._path)
        except Exception:
            logger.debug("could not persist reasoning quota (read-only fs?)")

    @staticmethod
    def _month() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    # -- tamper evidence (CR-LIC-01 AC-3) -----------------------------------
    # A sibling record in the user-level ``~/.graqle`` dir, keyed by project, so that
    # deleting or corrupting the project-local file is not a counter reset: the count
    # resumes from the higher of the two. Local and simple; ADR-245 still accepts
    # deliberate local edits of both files. If the user dir is unavailable the project
    # file alone counts - enforcement is never relaxed by a marker fault.

    def _marker_path(self) -> Path | None:
        try:
            override = os.environ.get(_USER_DIR_ENV)
            if override and override.strip() and _under_pytest():
                base = Path(override)
            else:
                base = Path.home() / ".graqle"
            return base / _MARKER_FILENAME
        except Exception:  # noqa: BLE001
            return None

    def _project_key(self) -> str:
        resolved = str(self._path.parent.resolve())
        return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]

    def _marker_read(self) -> dict:
        path = self._marker_path()
        try:
            if path is not None and path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:  # noqa: BLE001
            logger.debug("reasoning quota marker unreadable")
        return {}

    def _marker_used(self, month: str) -> int:
        try:
            project = self._marker_read().get(self._project_key())
            return _as_count(project.get(month)) if isinstance(project, dict) else 0
        except Exception:  # noqa: BLE001
            return 0

    def _marker_store(self, month: str, used: int) -> None:
        path = self._marker_path()
        if path is None:
            return
        try:
            data = self._marker_read()
            key = self._project_key()
            project = data.get(key)
            project = dict(project) if isinstance(project, dict) else {}
            project[month] = max(used, _as_count(project.get(month)))
            data[key] = _prune_old_months(project, month)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                os.replace(tmp_name, path)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except Exception:  # noqa: BLE001 - marker is best-effort; project file still counts
            logger.debug("could not persist reasoning quota marker")

    def _used(self, month: str) -> int:
        """Higher of the project-local count and the user-level marker."""
        return max(_as_count(self._load().get(month)), self._marker_used(month))

    def peek(self) -> QuotaReading:
        """Current usage without recording. Paid (or enforcement off) → allowed.

        Mirrors ``check_and_record``'s short-circuit exactly. Checking only the tier
        here made the two disagree: with ``GRAQLE_ENFORCE_CAPS=0`` at 30/30, ``peek()``
        reported ``allowed=False`` while ``check_and_record`` let the call through, so
        any status surface reading ``peek`` would tell a user they were blocked when
        they were not. Nothing user-facing consumes ``peek`` today — its only caller is
        the exempt-path short-circuit below — but the two must not be allowed to drift.
        """
        month = self._month()
        if _paid_tier() or not quota_enforcement_enabled():
            return QuotaReading(used=0, limit=-1, month=month, allowed=True)
        used = self._used(month)
        return QuotaReading(
            used=used,
            limit=FREE_REASONS_PER_MONTH,
            month=month,
            allowed=used < FREE_REASONS_PER_MONTH,
        )

    @contextmanager
    def _locked(self):
        """Hold an exclusive cross-process lock on the quota file.

        Concurrent reasoning runs otherwise race the read-modify-write below: two
        processes both read ``used=29``, both write ``30``, and the free cap leaks an
        extra call per racing process. The lock is advisory and best-effort — if the
        platform lock is unavailable we still proceed (fail-open), because a metering
        hiccup must never break reasoning.
        """
        lock_path = self._path.with_suffix(".lock")
        handle = None
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = open(lock_path, "a+b")  # noqa: SIM115 — released in finally
            if msvcrt is not None:  # Windows
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            elif fcntl is not None:  # POSIX
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except Exception as exc:  # noqa: BLE001 — lock unavailable → proceed unlocked
            logger.debug("reasoning quota lock unavailable: %s", exc)
        try:
            yield
        finally:
            if handle is not None:
                try:
                    if msvcrt is not None:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    elif fcntl is not None:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except Exception:  # noqa: BLE001 — closing releases it regardless
                    logger.debug("reasoning quota lock release failed")
                handle.close()

    def check_and_record(self, *, internal: bool = False) -> QuotaReading:
        """Enforce + record ONE reasoning invocation.

        Parameters
        ----------
        internal:
            When True (reasoning invoked by another metered action, e.g. a PR-Guardian
            scan), the call is EXEMPT — not counted, never blocked. Prevents W2/W3
            double-charging one user action.

        Raises
        ------
        ReasoningQuotaExceeded
            when enforcement is on, the tier is FREE, and the monthly quota is used up.

        Never raises on a metering/file error — reasoning must not break on a quota
        hiccup (fail-open).
        """
        if internal or not quota_enforcement_enabled() or _paid_tier():
            return self.peek()
        try:
            month = self._month()
            # Read-modify-write must be atomic across processes: without the lock two
            # concurrent runs both read the same `used` and both write used+1, leaking
            # one extra free call per racing process.
            with self._locked():
                data = self._load()
                used = max(_as_count(data.get(month)), self._marker_used(month))
                if used >= FREE_REASONS_PER_MONTH:
                    raise ReasoningQuotaExceeded(used, FREE_REASONS_PER_MONTH, month)
                data[month] = used + 1
                data["schema_version"] = _SCHEMA_VERSION
                self._store(_prune_old_months(data, month))
                self._marker_store(month, used + 1)
            return QuotaReading(
                used=used + 1,
                limit=FREE_REASONS_PER_MONTH,
                month=month,
                allowed=True,
            )
        except ReasoningQuotaExceeded:
            raise
        except Exception as exc:  # noqa: BLE001 — never break reasoning on a meter fault
            logger.debug("reasoning quota metering skipped: %s", exc)
            return QuotaReading(
                used=0, limit=FREE_REASONS_PER_MONTH, month=self._month(), allowed=True
            )
