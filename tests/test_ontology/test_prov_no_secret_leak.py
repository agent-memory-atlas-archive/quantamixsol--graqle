"""CR-016 PR-016c AC-10: the export never contains the TS-2/TS-3 payloads."""

from __future__ import annotations

import pytest

pytest.importorskip("rdflib")

from graqle.ontology.prov_export import NEVER_EXPORTED, export_prov, serialize  # noqa: E402
from tests.test_ontology._assurance_fixtures import conformant_graph  # noqa: E402

AT = "2026-10-01T00:00:00Z"
SENTINELS = {
    "confidence_vector_json": '{"sentinel_conf": 0.123456}',
    "score_vector_json": '{"sentinel_score": 0.654321}',
    "conditions": '{"sentinel_cond": "zz-cond-9"}',
}


def _graph_with_sentinels() -> dict:
    g = conformant_graph()
    for n in g["nodes"]:
        for k, v in SENTINELS.items():
            if k in n:
                n[k] = v
    return g


@pytest.mark.parametrize("fmt", ["turtle", "json-ld", "nt", "xml"])
def test_serialised_output_has_no_secret_names_or_values(fmt: str) -> None:
    g = _graph_with_sentinels()
    assert all(any(k in n for n in g["nodes"]) for k in SENTINELS), "fixture must carry all three"
    text = serialize(export_prov(g, at_iso=AT), fmt).decode("utf-8")
    for name in NEVER_EXPORTED:
        assert name not in text
    for needle in ("sentinel_conf", "sentinel_score", "sentinel_cond", "zz-cond-9", "0.123456"):
        assert needle not in text


def test_versions_are_exported_but_vectors_are_not() -> None:
    text = serialize(export_prov(_graph_with_sentinels(), at_iso=AT)).decode("utf-8")
    assert "cv-sub" in text  # confidence_vector_version is an ordinary, exportable string
    assert NEVER_EXPORTED == {"confidence_vector_json", "score_vector_json", "conditions"}
