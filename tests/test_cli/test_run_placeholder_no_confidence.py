"""CR-README-02: a placeholder answer must never carry a confidence figure.

The defect this pins: with no LLM backend configured, ``graq run`` printed

    [NO LLM CONFIGURED — this is a placeholder response, not real AI reasoning...]
    Confidence: 62% | Rounds: 2 | Nodes: 5 | ...

The answer text said "placeholder"; the summary line underneath said "62%".
In a screenshot or a terminal scrollback that is indistinguishable from a
governed answer, which undermines every decision-grade claim the project
makes about confidence and evidence.

THIS TEST EXISTS BECAUSE TWO EARLIER FIXES BOTH MISSED.

  Attempt 1 fixed ``graqle/backends/mock.py`` — the backend's *answer text*.
  The CLI's own summary line kept printing the number.

  Attempt 2 guarded the print sites inside ``def reason()``. But ``graq run``
  dispatches to ``def run()`` (main.py:401), a *different* function with its
  own print site. The number kept printing, and a source-grep test written
  at the same time passed anyway — a false green, because it asserted on
  strings that existed in the wrong function.

The lesson encoded here: assert on the *observable CLI behaviour* of each
command that prints confidence, not on the presence of source strings
somewhere in a 3,000-line module.

Why not key on ``backend_status``: that field is only ever set to ``"failed"``
on an exception (``graqle/core/graph.py``). The mock-fallback path leaves it
at its ``"ok"`` default, so it cannot distinguish a real answer from a
placeholder. ``MockBackend.is_fallback`` is the signal that tracks the
condition, and the bench command already fail-fasts on it.
"""

from __future__ import annotations

import asyncio
import pathlib
import re

import pytest

from graqle.backends.mock import MockBackend

MAIN_PY = (
    pathlib.Path(__file__).resolve().parents[2] / "graqle" / "cli" / "main.py"
)

#: Percentage-shaped confidence, e.g. "Confidence: 62%".
_CONF_PCT = re.compile(r"Confidence:\s*\d+\s*%")


# ---------------------------------------------------------------------------
# The signal itself
# ---------------------------------------------------------------------------


class TestFallbackBackendSignal:
    def test_fallback_backend_reports_is_fallback(self) -> None:
        assert MockBackend(is_fallback=True).is_fallback is True

    def test_explicit_mock_is_not_a_fallback(self) -> None:
        """An explicitly-constructed mock is a legitimate test double.

        Only the silent no-backend-configured fallback suppresses the figure.
        """
        assert MockBackend().is_fallback is False


# ---------------------------------------------------------------------------
# The backend's answer text (attempt-1 regression)
# ---------------------------------------------------------------------------


class TestPlaceholderAnswerText:
    def test_fallback_text_carries_no_percentage(self) -> None:
        result = asyncio.run(MockBackend(is_fallback=True).generate("anything"))
        assert "NO LLM CONFIGURED" in result.text
        assert not _CONF_PCT.search(result.text), (
            f"placeholder answer embeds a confidence figure: {result.text!r}"
        )

    def test_scripted_mock_still_reports_confidence(self) -> None:
        """Guard against over-correcting: the scripted path is unchanged."""
        result = asyncio.run(MockBackend(is_fallback=False).generate("x"))
        assert _CONF_PCT.search(result.text)


# ---------------------------------------------------------------------------
# Every CLI print site (attempt-2 regression)
# ---------------------------------------------------------------------------


def _function_source(name: str) -> str:
    """Return the source of top-level ``def <name>(`` up to the next def.

    Scoping the search to one function is the whole point: attempt 2 passed
    a source-grep test while the defect lived in a different function.
    """
    src = MAIN_PY.read_text(encoding="utf-8")
    lines = src.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith(f"def {name}(")), None
    )
    assert start is not None, f"def {name}( not found in main.py"
    end = next(
        (
            j
            for j in range(start + 1, len(lines))
            if lines[j].startswith("def ") or lines[j].startswith("@app.command")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


#: Every command function in main.py that prints a confidence figure and
#: creates its own backend. If a new one is added, add it here.
_COMMANDS_THAT_PRINT_CONFIDENCE = ["run", "reason", "safety_check_command"]


@pytest.mark.parametrize("func", _COMMANDS_THAT_PRINT_CONFIDENCE)
def test_every_confidence_print_is_guarded(func: str) -> None:
    """No command may print raw ``result.confidence`` unguarded.

    Each function that displays a confidence figure must first consult
    ``backend.is_fallback``. This catches the exact miss of attempt 2, where
    one function was guarded and another was not.
    """
    body = _function_source(func)

    if not _CONF_PCT.sub("", body) or "Confidence:" not in body:
        pytest.skip(f"{func} no longer prints a confidence figure")

    assert 'getattr(backend, "is_fallback", False)' in body, (
        f"{func}() prints a confidence figure without consulting "
        f"backend.is_fallback. An unconfigured install will show a "
        f"percentage next to placeholder text."
    )
    assert "not reported (no LLM configured)" in body, (
        f"{func}() has no no-LLM branch for its confidence display."
    )


#: Confidence values that originate from an LLM reasoning result. Only these
#: can be contaminated by the no-backend fallback.
#:
#: Deliberately NOT included: ``profile.confidence`` (domain detection),
#: ``env.confidence`` (environment provider detection) and ``rec.confidence``
#: (strategy recommendation). Those are computed locally from the graph and
#: are meaningful with no LLM configured, so suppressing them would be wrong.
#: Scoping this sweep is the point — a blanket rule would have to be weakened
#: to pass, and a weakened guard is how this defect survived two fixes.
_REASONING_CONF = re.compile(r"\b(?:result|r)\.confidence:\.0%")


def test_no_unguarded_reasoning_confidence_remains() -> None:
    """Every printed *reasoning* confidence sits inside an is_fallback branch.

    A raw percentage is acceptable only where the code has already tested
    ``backend.is_fallback``, or in the JSON output path (machine-read, and it
    carries ``backend_status`` alongside).
    """
    lines = MAIN_PY.read_text(encoding="utf-8").splitlines()
    offenders: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        if not _REASONING_CONF.search(ln):
            continue
        if '"confidence":' in ln:  # JSON payload, not a rendered line
            continue
        window = "\n".join(lines[max(0, i - 14) : i + 1])
        if 'getattr(backend, "is_fallback", False)' in window:
            continue
        offenders.append((i + 1, ln.strip()))
    assert not offenders, (
        "unguarded reasoning-confidence percentages at main.py lines: "
        + "; ".join(f"{n}: {t[:70]}" for n, t in offenders)
    )
