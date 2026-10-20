"""Shared cap-enforcement decision (CR-LIC-01) — one helper for every wall.

The reasoning-quota wall, the node-cap meter and ``graq doctor`` all ask the same
question: *are the free-tier caps enforced for this process?*

Enforcement is ON by default. ``GRAQLE_ENFORCE_CAPS`` can request an opt-out, but a
self-attested environment variable is not a licence: the opt-out is honoured ONLY when

  (a) the VERIFIED licence is a paid tier (the walls are already off for it, so the flag
      is a no-op), or
  (b) the process is genuinely running under pytest (checked via ``sys.modules``, which a
      production process cannot forge by exporting a variable).

In every other case the flag is ignored and a one-line notice says so.
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger("graqle.licensing.caps")

__all__ = ["ENFORCE_ENV", "caps_enforced", "caps_state", "paid_tier", "under_pytest"]

ENFORCE_ENV = "GRAQLE_ENFORCE_CAPS"
_FALSY = frozenset({"0", "false", "no", "off", ""})

_notice_shown = False


def under_pytest() -> bool:
    """True only when pytest is genuinely loaded in THIS process (not an env variable)."""
    return "pytest" in sys.modules or "_pytest" in sys.modules


def paid_tier() -> bool:
    """True iff the VERIFIED licence is a paid tier (Pro/Team/Enterprise).

    Fail-safe: any error → treat as FREE (caps enforced).
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


def _opt_out_requested() -> bool:
    raw = os.environ.get(ENFORCE_ENV)
    return raw is not None and raw.strip().lower() in _FALSY


def caps_enforced() -> bool:
    """True when the free-tier caps apply to this process (the default)."""
    global _notice_shown  # noqa: PLW0603
    if not _opt_out_requested():
        return True
    if paid_tier() or under_pytest():
        return False
    if not _notice_shown:
        _notice_shown = True
        logger.warning(
            "%s is ignored: free-tier limits are enforced without a verified paid licence.",
            ENFORCE_ENV,
        )
    return True


def caps_state() -> str:
    """Human label for ``graq doctor``: state only, never limit values."""
    return "off (paid licence)" if paid_tier() else "enforced"
