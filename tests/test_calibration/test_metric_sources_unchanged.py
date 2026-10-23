"""CR-014 AC-7 — existing metric functions are byte-identical after PR-014a."""

from __future__ import annotations

import hashlib
import inspect

import pytest

import graqle.calibration.metrics as metrics

#: SHA-256 of each function's source (LF-normalised) as it stood before CR-014.
GOLDEN: dict[str, str] = {
    "_validate_inputs": "339a414aad1e67bf3db5d9a942448f037a58d52543829356764ae22d931d061c",
    "compute_ece": "4b46cd1bfba2384d843508d60fb789dd2ad48264e683c1559054a049674ada31",
    "compute_mce": "435d6f99d08bc0ce9036f2750cc8c32ace66c7aed24abc30fb4f57970e3fedc8",
    "compute_brier_score": "a59baca634d0cd6682d6734c5145e6ae28e16925b81b224e6844eeafdac4adc5",
}


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_existing_function_source_unchanged(name: str) -> None:
    src = inspect.getsource(getattr(metrics, name)).replace("\r\n", "\n")
    assert hashlib.sha256(src.encode("utf-8")).hexdigest() == GOLDEN[name]


def test_module_stays_numpy_only() -> None:
    src = inspect.getsource(metrics)
    for banned in ("import scipy", "from scipy", "import sklearn", "from sklearn"):
        assert banned not in src
