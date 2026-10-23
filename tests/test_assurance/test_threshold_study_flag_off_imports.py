"""AC-22: with the flag unset, importing the CLI pulls no confidence-vector module."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_import_does_not_load_confidence_vector_modules() -> None:
    code = (
        "import sys, graqle.cli.commands.assurance; "
        "bad = [m for m in sys.modules if m in ("
        "'graqle.assurance.confidence_vector', 'graqle.assurance.threshold_study', "
        "'graqle.assurance.cv_settings')]; "
        "assert not bad, bad"
    )
    env = {k: v for k, v in os.environ.items() if k != "GRAQLE_DAG_ENABLED"}
    subprocess.run([sys.executable, "-c", code], cwd=_REPO_ROOT, env=env, check=True)
