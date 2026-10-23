"""CR-013 AC-12 — HG-04 arguments binding."""

from __future__ import annotations

import ast
import inspect
import textwrap

import pytest

from graqle.assurance.hard_gates import HG04ArgsBinding

from ._builders import make_ctx, make_settings

GATE = HG04ArgsBinding()
S = make_settings()
ALGO = S.args_hash_algo


def _ctx(**kw):  # type: ignore[no-untyped-def]
    base = {
        "approved_args_hash": "ab" * 8,
        "approved_args_algo": ALGO,
        "actual_args_hash": "ab" * 8,
        "actual_args_algo": ALGO,
    }
    base.update(kw)
    return make_ctx(**base)


def test_matching_binding_passes() -> None:
    assert GATE.evaluate(_ctx(), S).passed


@pytest.mark.parametrize("field", ["approved_args_hash", "actual_args_hash"])
def test_absent_hash_is_binding_absent(field: str) -> None:
    r = GATE.evaluate(_ctx(**{field: None}), S)
    assert not r.passed
    assert r.reason_codes == ("DAG-HG04-BINDING_ABSENT",)


@pytest.mark.parametrize("field", ["approved_args_algo", "actual_args_algo"])
def test_algo_mismatch(field: str) -> None:
    r = GATE.evaluate(_ctx(**{field: "other-algo"}), S)
    assert r.reason_codes == ("DAG-HG04-ARGS_HASH_ALGO_MISMATCH",)


def test_both_algos_wrong_but_equal_fails_against_settings() -> None:
    r = GATE.evaluate(_ctx(approved_args_algo="x", actual_args_algo="x"), S)
    assert not r.passed


def test_hash_mismatch() -> None:
    r = GATE.evaluate(_ctx(actual_args_hash="cd" * 8), S)
    assert r.reason_codes == ("DAG-HG04-ARGS_HASH_MISMATCH",)


def test_projection_has_hashes_only() -> None:
    assert set(GATE.project(_ctx())) == {"approved", "approved_algo", "actual", "actual_algo"}


def test_compare_uses_hmac_compare_digest_and_no_equality_on_hashes() -> None:
    tree = ast.parse(textwrap.dedent(inspect.getsource(HG04ArgsBinding._predicate)))
    calls = [
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]
    assert "compare_digest" in calls
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            operands = [n.left, *n.comparators]
            touches_hash = any(
                isinstance(x, ast.Attribute) and x.attr in {"approved_args_hash", "actual_args_hash"}
                for x in operands
            )
            if touches_hash:
                assert all(isinstance(op, (ast.Is, ast.IsNot)) for op in n.ops)
