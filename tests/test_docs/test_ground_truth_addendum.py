"""CR-012 AC-6 — ``docs/dag/ground-truth-addendum.md`` exists and carries the
eight rows of CR-012 §0.3 (string match on the file:line citations).

See: .gsm/external/Change Requests/DAG-2026/
     CR-012-DAG-foundation-flag-schema-reason-codes-hygiene.md §0.3
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADDENDUM = _REPO_ROOT / "docs" / "dag" / "ground-truth-addendum.md"

# (charter claim fragment, source citation) — verbatim from CR-012 §0.3.
_ROWS: tuple[tuple[str, str], ...] = (
    (
        "≥0.70 accept / 0.40–0.69 hold / <0.40 reject",
        "`core/governance.py:283-284, 793-930`",
    ),
    ('"confidence" gate', "`core/governance.py:742-750`"),
    ("Article 14 human-review threshold", "`compliance/article_14_gate.py:64`, `settings.py:560`"),
    (
        '"Five deterministic scoring dimensions"',
        "`intelligence/governance/drace.py:74-90, 266-288`",
    ),
    (
        '"Decision trail hashes"',
        "`governance/tamper_evidence/*`, `compliance/eu_ai_act_latch.py:216`, "
        "`intelligence/governance/audit.py:68`",
    ),
    ("EXECUTE/REPLAN/HOLD/REJECT/ESCALATE as current outcomes", "`governance/trace_schema.py:53`"),
    ("Reason-code registry", "`trace_schema.py:108`"),
    ("`assurance.enabled` config key", "this CR §3.3"),
)


def test_addendum_exists() -> None:
    assert _ADDENDUM.is_file(), f"missing {_ADDENDUM}"


@pytest.mark.parametrize(("claim", "source"), _ROWS, ids=[r[0][:24] for r in _ROWS])
def test_addendum_has_row(claim: str, source: str) -> None:
    text = _ADDENDUM.read_text(encoding="utf-8")
    assert claim in text, f"charter claim missing from addendum: {claim!r}"
    assert source in text, f"source citation missing from addendum: {source!r}"


def test_addendum_has_exactly_eight_table_rows() -> None:
    text = _ADDENDUM.read_text(encoding="utf-8")
    table_rows = [
        line for line in text.splitlines()
        if line.startswith("| ")
        and not line.startswith("| Charter")
        and not line.startswith("|---")
    ]
    assert len(table_rows) == 8, table_rows


def test_addendum_states_no_hold_band_and_flag_derivation() -> None:
    text = _ADDENDUM.read_text(encoding="utf-8")
    assert "**no hold band**" in text
    assert "DERIVED from `GRAQLE_DAG_ENABLED`" in text
