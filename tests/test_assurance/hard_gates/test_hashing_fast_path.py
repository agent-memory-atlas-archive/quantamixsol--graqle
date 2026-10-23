"""CR-B17-PERF: the inputs_hash fast path is byte-identical to the JCS canonicaliser."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from graqle.assurance._hashing import _fast_canon, inputs_hash
from graqle.governance.tamper_evidence.canonicalize import canon

SIMPLE: list[dict[str, Any]] = [
    {},
    {"a": []},
    {"b": 1, "a": 2},  # int leaf: not on the fast path, still canonical
    {"z": ["x", None, True, False], "a": {"k": "v", "j": [["n1", "ACTIVE", False, True]]}},
    {"pairs": [[["a1", "b1"], ["s1", "s2"], 0.1, None]]},
    {"f": [0.25, 3.5, 0.1]},
    {"s": "it's plain ascii ~"},
]

FAST: list[dict[str, Any]] = [SIMPLE[0], SIMPLE[1], SIMPLE[3], SIMPLE[4], SIMPLE[5], SIMPLE[6]]

NOT_FAST: list[dict[str, Any]] = [
    {"s": 'quote " inside'},
    {"s": "back\\slash"},
    {"s": "tab\tinside"},
    {"s": "del \x7f"},
    {"s": "café"},
    {"s": "astral \U0001f600"},
    {"s": "lone \ud800 surrogate"},
    {"f": 1.0},
    {"f": 1e-7},
    {"f": 1e22},
    {"f": -0.0},
    {"f": [0.5, 2.0]},
    {"i": 10**20},
    {"t": ("a", "b")},
    {1: "int key"},
]


@pytest.mark.parametrize("projection", SIMPLE)
def test_hash_equals_canonical_bytes(projection: dict[str, Any]) -> None:
    expected = "sha256:" + hashlib.sha256(canon(projection)).hexdigest()
    assert inputs_hash(projection) == expected


@pytest.mark.parametrize("projection", FAST)
def test_fast_path_bytes_equal_canon(projection: dict[str, Any]) -> None:
    assert _fast_canon(projection) == canon(projection)


@pytest.mark.parametrize("projection", NOT_FAST)
def test_unsafe_shapes_decline_the_fast_path(projection: dict[str, Any]) -> None:
    assert _fast_canon(projection) is None


def test_non_finite_float_still_fails_closed() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        assert _fast_canon({"f": bad}) is None
        with pytest.raises(Exception):
            inputs_hash({"f": bad})


def test_tuple_still_rejected_by_the_canonicaliser() -> None:
    with pytest.raises(Exception):
        inputs_hash({"t": ("a", "b")})
