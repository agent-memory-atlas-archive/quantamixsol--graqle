"""CR-016 AC-5 — bitemporal validation and the ``covers`` predicate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import settings as h_settings
from hypothesis import strategies as st
from pydantic import ValidationError

from graqle.governance.custody.ed25519_key_manifest import _as_utc
from graqle.ontology.assurance import (
    BitemporalMixin,
    covers,
    current_state_cypher_predicate,
    to_iso_utc,
)

UTC = timezone.utc
_dt = st.datetimes(
    min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1), timezones=st.just(UTC)
).map(lambda d: d.replace(microsecond=0))


@pytest.mark.parametrize(
    "bad",
    [
        "2026-07-01T00:00:00",  # naive
        "2026-07-01T00:00:00+02:00",  # non-UTC offset
        "2026-07-01T00:00:00.5Z",  # non-canonical width breaks string ordering
        "2026-02-30T00:00:00Z",  # impossible date
        1_751_328_000,  # not a string
        datetime(2026, 7, 1, tzinfo=UTC),  # not a string
    ],
)
def test_rejects_non_canonical_timestamps(bad: object) -> None:
    with pytest.raises(ValidationError):
        BitemporalMixin(valid_from=bad, asserted_at="2026-07-01T00:00:00Z")


@pytest.mark.parametrize(
    "fields",
    [
        {"valid_from": "2026-07-02T00:00:00Z", "valid_until": "2026-07-01T00:00:00Z"},
        {"asserted_at": "2026-07-02T00:00:00Z", "retracted_at": "2026-07-01T00:00:00Z"},
    ],
)
def test_rejects_inverted_windows(fields: dict) -> None:
    base = {"valid_from": "2026-07-01T00:00:00Z", "asserted_at": "2026-07-01T00:00:00Z"}
    with pytest.raises(ValidationError, match="precedes"):
        BitemporalMixin(**{**base, **fields})


@h_settings(max_examples=300, deadline=None)
@given(a=_dt, b=_dt)
def test_canonical_strings_order_like_time(a: datetime, b: datetime) -> None:
    assert (to_iso_utc(a) < to_iso_utc(b)) == (a < b)


@h_settings(max_examples=300, deadline=None)
@given(vf=_dt, span=st.integers(1, 10**8), at=_dt)
def test_covers_agrees_with_key_window_except_at_the_open_end(
    vf: datetime, span: int, at: datetime
) -> None:
    """KeyEntry.is_within_window is inclusive [vf, vu]; CR-016 §2.2 is half-open [vf, vu)."""
    vu = vf + timedelta(seconds=span)
    node = {
        "valid_from": to_iso_utc(vf),
        "valid_until": to_iso_utc(vu),
        "asserted_at": to_iso_utc(vf),
    }
    inclusive = _as_utc(vf) <= _as_utc(at) <= _as_utc(vu)
    ours = covers(node, at, at_tx=vu)
    if at == vu:
        assert inclusive and not ours
    else:
        assert ours == inclusive


def test_supersession_instant_has_exactly_one_current_version() -> None:
    old = {
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-06-01T00:00:00Z",
        "asserted_at": "2026-01-01T00:00:00Z",
    }
    new = {"valid_from": "2026-06-01T00:00:00Z", "asserted_at": "2026-01-01T00:00:00Z"}
    at = datetime(2026, 6, 1, tzinfo=UTC)
    assert [covers(old, at), covers(new, at)] == [False, True]


def test_transaction_time_is_respected() -> None:
    node = {
        "valid_from": "2026-01-01T00:00:00Z",
        "asserted_at": "2026-03-01T00:00:00Z",
        "retracted_at": "2026-04-01T00:00:00Z",
    }
    at = datetime(2026, 2, 1, tzinfo=UTC)
    assert not covers(node, at)  # not yet asserted
    assert covers(node, at, at_tx=datetime(2026, 3, 15, tzinfo=UTC))
    assert not covers(node, at, at_tx=datetime(2026, 4, 1, tzinfo=UTC))  # retracted


def test_naive_query_times_are_rejected() -> None:
    node = {"valid_from": "2026-01-01T00:00:00Z", "asserted_at": "2026-01-01T00:00:00Z"}
    with pytest.raises(ValueError, match="naive"):
        covers(node, datetime(2026, 2, 1))


def test_cypher_predicate_shape_and_alias_guard() -> None:
    frag = current_state_cypher_predicate("n")
    assert frag.startswith("(n.assurance_type IS NULL OR (")
    assert "$now" in frag and "$at" not in frag
    assert "$at" in current_state_cypher_predicate("m", at_param=True)
    assert current_state_cypher_predicate(historical=True) == "true"
    with pytest.raises(ValueError, match="identifier"):
        current_state_cypher_predicate("n) DETACH DELETE (x")
