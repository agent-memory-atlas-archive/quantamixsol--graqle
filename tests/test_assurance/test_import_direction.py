"""CR-012 AC-21 / ruling N5 — the assurance layer's dependency direction.

`.importlinter` catches EAGER, module-level violations statically. This module
asserts the invariant N5 actually specifies: at RUNTIME, with the flag off,
importing a pre-existing module must not pull `graqle.assurance` into
`sys.modules`. The three `config/settings.py` references are inside function and
property bodies, so the static graph sees edges that never execute at import.
"""

from __future__ import annotations

import subprocess
import sys

_PROBE = """
import sys
import {module}
leaked = sorted(m for m in sys.modules if m.startswith("graqle.assurance"))
print(",".join(leaked))
"""


def _assurance_modules_loaded_by(module: str) -> list[str]:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE.format(module=module)],
        capture_output=True,
        text=True,
        check=True,
    )
    out = result.stdout.strip()
    return [m for m in out.split(",") if m]


class TestRuntimeImportDirection:
    def test_governance_does_not_load_assurance(self) -> None:
        assert _assurance_modules_loaded_by("graqle.governance") == []

    def test_kg_write_gate_does_not_load_assurance(self) -> None:
        # The static graph flags kg_write_gate -> config.settings -> assurance;
        # at runtime the config.settings edge is TYPE_CHECKING-only and the
        # assurance edges are lazy, so nothing is loaded.
        assert _assurance_modules_loaded_by("graqle.governance.kg_write_gate") == []

    def test_trace_schema_does_not_load_assurance(self) -> None:
        # This is why GateVerdictRef is duplicated rather than imported.
        assert _assurance_modules_loaded_by("graqle.governance.trace_schema") == []

    def test_config_settings_does_not_load_assurance_with_the_flag_off(self) -> None:
        assert _assurance_modules_loaded_by("graqle.config.settings") == []


class TestAssuranceMayImportGovernance:
    def test_direction_is_one_way(self) -> None:
        # The permitted direction: assurance -> governance.
        import graqle.assurance  # noqa: F401
        import graqle.governance  # noqa: F401
