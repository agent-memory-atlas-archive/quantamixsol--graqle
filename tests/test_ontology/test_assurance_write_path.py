"""CR-016 PR-016b unit tests: ops, digests, verifier fail-closed, connector, config, AST gate.

No database. The live Neo4j proofs (the ten failing cases, AC-6/7/8) are in
test_assurance_neo4j_integration.py and run only against a scratch Community
Edition server.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from graqle.connectors import neo4j as n4j
from graqle.governance.tamper_evidence.kg_persist import (
    AssuranceWriteRefusedError,
    KgPersistError,
    Neo4jBatchPersister,
    _is_constraint_rejection,
)
from graqle.ontology.assurance import EdgeKind
from graqle.ontology.assurance_integrity import (
    EDGE_DIGEST_FIELDS,
    NODE_DIGEST_FIELDS,
    IntegrityKeyring,
    edge_digest,
    node_digest,
    ordering_violation,
    verify_assurance_integrity,
    verify_digest,
)
from graqle.ontology.assurance_ops import RESERVED_PROPS, WRITE_ONCE_NODE_FIELDS, AssuranceOp

sys.path.insert(0, str(Path(__file__).parent))
from _assurance_write_fixtures import (  # noqa: E402
    KEYRING,
    SALT,
    SALT_NEXT,
    SUBSTRATE_EDGES,
    SUBSTRATE_NODES,
    FakeDriver,
    calls_digest,
    claim,
    claim_op,
    edge_op,
)

ROOT = Path(__file__).resolve().parents[2]

#: Captured from the private/master connector (fe659861) with the same fake
#: driver and fixture graph, flag off. Any change is an AC-1 regression.
GOLDEN_SAVE = "351c4e0d3f0f2f57755053df45efed31d0ace05a63cdc427873a16c6f4838d68"
GOLDEN_SCHEMA = "81c59404cb06e3d0d4e04a0cbc0bb9acf36536f863eb9c694f76ded2bed22d12"

T_OLD = ("2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z")  # (valid_from, asserted_at)
T_NEW = ("2026-09-02T00:00:00Z", "2026-09-02T00:00:00Z")


# ── AC-1: flag off is byte-identical ─────────────────────────────────────────


def _connector(monkeypatch: pytest.MonkeyPatch, flag: str | None = None) -> tuple[Any, FakeDriver]:
    if flag is None:
        monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    else:
        monkeypatch.setenv("GRAQLE_DAG_ENABLED", flag)
    c = n4j.Neo4jConnector()
    d = FakeDriver()
    c._driver = d
    return c, d


def test_ac1_save_without_assurance_data_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    c, d = _connector(monkeypatch)
    c.save(SUBSTRATE_NODES, SUBSTRATE_EDGES)
    assert calls_digest(d.calls) == GOLDEN_SAVE


def test_ac1_create_schema_flag_off_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    c, d = _connector(monkeypatch)
    c.create_schema()
    assert calls_digest(d.calls) == GOLDEN_SCHEMA


def test_create_schema_flag_on_adds_indexes_and_constraints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, d = _connector(monkeypatch, "true")
    c.create_schema()
    stmts = [q for q, _ in d.calls]
    assert calls_digest(d.calls[:3]) == GOLDEN_SCHEMA  # the flag-off prefix is untouched
    joined = "\n".join(stmts)
    for name in (
        "assurance_version_unique",
        "relates_to_supersedes_in",
        "relates_to_corrects_out",
        "relates_to_kind",
    ):
        assert name in joined
    assert all("IF NOT EXISTS" in q for q in stmts[3:])


# ── AC-8 (offline half): the closed allowlist pass-through ───────────────────


def test_save_passes_through_only_the_allowlisted_edge_props(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, d = _connector(monkeypatch)
    edges = {
        "k1": {
            "source": "a.py",
            "target": "b.py",
            "relationship": "RELATES_TO",
            "properties": {
                "kind": "SUPPORTED_BY",
                "strength": 0.8,
                "scope_key": "s",
                "rogue": "x",
                "supersedes_in": "b.py",
                "nested": {"x": 1},
            },
        }
    }
    c.save({}, edges)
    ((query, params),) = d.calls
    assert query.endswith("r += row.props")
    assert params["rows"][0]["props"] == {"kind": "SUPPORTED_BY", "strength": 0.8, "scope_key": "s"}


def test_save_skips_ordered_edges_and_leaves_them_to_the_write_path(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    c, d = _connector(monkeypatch)
    edges = {
        "s": {
            "source": "a",
            "target": "b",
            "relationship": "RELATES_TO",
            "properties": {"kind": "SUPERSEDES"},
        },
        "k": {"source": "a", "target": "b", "relationship": "RELATES_TO", "kind": "CORRECTS"},
    }
    c.save({}, edges)
    assert d.calls == []
    assert "skipped 2 SUPERSEDES/CORRECTS" in caplog.text


def test_save_never_writes_write_once_fields_of_an_assurance_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, d = _connector(monkeypatch)
    node = {
        "label": "c1",
        "type": "ASSURANCE_CLAIM",
        "properties": {**claim("c1", "cid", *T_NEW), "integrity_digest": "forged"},
    }
    c.save({"c1": node}, {})
    row = d.calls[0][1]["rows"][0]
    assert not set(WRITE_ONCE_NODE_FIELDS) & set(row)
    assert "integrity_digest" not in row
    assert row["subject"] == "s"  # ordinary properties still flow


def test_connector_constants_match_the_ops_module() -> None:
    assert n4j._ASSURANCE_WRITE_ONCE == WRITE_ONCE_NODE_FIELDS
    assert n4j._ASSURANCE_RESERVED == RESERVED_PROPS
    assert n4j._ORDERED_EDGE_KINDS == {"SUPERSEDES", "CORRECTS"}


# ── ops ──────────────────────────────────────────────────────────────────────


def test_ops_reject_reserved_props_and_non_canonical_timestamps() -> None:
    with pytest.raises(ValueError, match="reserved"):
        AssuranceOp(kind="create_node", node_id="x", props={"supersedes_in": "y"})
    with pytest.raises(ValueError):
        AssuranceOp.set_if_absent(
            "x", {"valid_from": "2026-09-30T12:00:00.5Z"}
        )  # fractional seconds banned
    with pytest.raises(ValueError, match="cannot write"):
        AssuranceOp.set_if_absent("x", {"canonical_id": "c"})
    with pytest.raises(ValueError):
        AssuranceOp.create_node(
            {**claim("x", "c", *T_NEW), "integrity_digest": "d"}
        )  # extra="forbid"


def test_create_edge_op_derives_the_id_and_never_carries_cardinality() -> None:
    op = edge_op("n", "o", EdgeKind.SUPERSEDES)
    assert op.edge_kind is EdgeKind.SUPERSEDES
    assert not RESERVED_PROPS & set(op.props)


# ── digests and keyring ──────────────────────────────────────────────────────


def test_digest_field_sets_are_the_ruled_ones() -> None:
    assert NODE_DIGEST_FIELDS == (
        "id",
        "assurance_type",
        "canonical_id",
        "scope_key",
        "valid_from",
        "asserted_at",
    )
    assert EDGE_DIGEST_FIELDS == (
        "source_id",
        "target_id",
        "kind",
        "scope_key",
        "prov_event_id",
        "asserted_at",
    )


def test_every_digest_field_changes_the_digest() -> None:
    node = {
        "id": "n",
        "assurance_type": "Claim",
        "canonical_id": "c",
        "scope_key": "s",
        "valid_from": T_NEW[0],
        "asserted_at": T_NEW[1],
    }
    base = node_digest(KEYRING, node)
    for f in NODE_DIGEST_FIELDS:
        assert node_digest(KEYRING, {**node, f: "changed"}) != base, f
    edge = {
        "source_id": "a",
        "target_id": "b",
        "kind": "SUPERSEDES",
        "scope_key": "s",
        "prov_event_id": "p",
        "asserted_at": T_NEW[1],
    }
    base_e = edge_digest(KEYRING, edge)
    for f in EDGE_DIGEST_FIELDS:
        assert edge_digest(KEYRING, {**edge, f: "changed"}) != base_e, f


def test_rotation_is_distinguishable_from_tampering() -> None:
    node = {"id": "n", "valid_from": T_NEW[0]}
    old = node_digest(KEYRING, node)
    rotated = IntegrityKeyring.from_salts(("v2", SALT_NEXT), ("v1", SALT))
    only_new = IntegrityKeyring.from_salts(("v2", SALT_NEXT))
    assert verify_digest(rotated, "node", node, old, "v1") == "OK"  # overlap window
    assert verify_digest(only_new, "node", node, old, "v1") == "UNKNOWN_VERSION"  # not "tampered"
    assert verify_digest(rotated, "node", {**node, "valid_from": T_OLD[0]}, old, "v1") == "MISMATCH"
    assert verify_digest(rotated, "node", node, None, None) == "MISSING"


def test_keyring_rejects_short_salts_and_duplicate_versions() -> None:
    with pytest.raises(ValueError):
        IntegrityKeyring.from_salts(("v1", "short"))
    with pytest.raises(ValueError):
        IntegrityKeyring.from_salts(("v1", SALT), ("v1", SALT_NEXT))
    assert "test-substitute" not in repr(KEYRING)


# ── ordering rule (d) ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kind", "src", "tgt", "bad"),
    [
        ("SUPERSEDES", T_NEW, T_OLD, False),
        ("SUPERSEDES", T_OLD, T_NEW, True),  # reversed
        ("CORRECTS", T_OLD, T_OLD, True),  # equal is not a strict decrease
        # later assertion, same valid_from: fine for CORRECTS, not for SUPERSEDES
        ("CORRECTS", (T_OLD[0], T_NEW[1]), T_OLD, False),
        ("SUPERSEDES", (T_OLD[0], T_NEW[1]), T_OLD, True),
        ("SUPERSEDES", ("2026-09-02T00:00:00.5Z", T_NEW[1]), T_OLD, True),  # non-canonical
    ],
)
def test_ordering_rule(kind: str, src: tuple[str, str], tgt: tuple[str, str], bad: bool) -> None:
    s = {"valid_from": src[0], "asserted_at": src[1]}
    t = {"valid_from": tgt[0], "asserted_at": tgt[1]}
    assert (ordering_violation(kind, s, t) is not None) is bad


# ── verifier fails closed ─────────────────────────────────────────────────────


class _RowsConnector:
    def __init__(self, rows: list[list[dict[str, Any]]] | Exception) -> None:
        self._rows = rows

    def read_assurance_rows(self, queries: list[Any]) -> list[list[dict[str, Any]]]:
        if isinstance(self._rows, Exception):
            raise self._rows
        return self._rows


def test_verifier_without_a_keyring_is_never_ok() -> None:
    rep = verify_assurance_integrity(_RowsConnector([[{"name": n} for n in ()], [], []]), None)
    assert not rep.ok and "VERIFIER_UNKEYED" in rep.codes()


def test_verifier_query_failure_is_never_ok() -> None:
    rep = verify_assurance_integrity(_RowsConnector(RuntimeError("down")), KEYRING)
    assert not rep.ok and rep.codes() == {"VERIFIER_QUERY_FAILED"}
    with pytest.raises(Exception, match="VERIFIER_QUERY_FAILED"):
        rep.raise_for_errors()


def test_verifier_flags_missing_constraints() -> None:
    rep = verify_assurance_integrity(_RowsConnector([[], [], []]), KEYRING)
    assert not rep.ok and "CONSTRAINT_MISSING" in rep.codes()


def test_verifier_checks_constraints_by_shape_not_by_name() -> None:
    from graqle.ontology.assurance_integrity import ASSURANCE_CONSTRAINT_SHAPES

    # Equivalent constraints under OTHER names (IF NOT EXISTS then no-ops) are
    # enforced, so they are not missing.
    renamed = [
        {"name": f"legacy_{i}", "type": t, "labelsOrTypes": [lt], "properties": list(p)}
        for i, (t, lt, p) in enumerate(ASSURANCE_CONSTRAINT_SHAPES.values())
    ]
    assert verify_assurance_integrity(_RowsConnector([renamed, [], []]), KEYRING).ok
    # The right NAME on the wrong shape is not enough.
    wrong = [
        {"name": n, "type": "RANGE", "labelsOrTypes": [lt], "properties": list(p)}
        for n, (_, lt, p) in ASSURANCE_CONSTRAINT_SHAPES.items()
    ]
    rep = verify_assurance_integrity(_RowsConnector([wrong, [], []]), KEYRING)
    assert not rep.ok and "CONSTRAINT_MISSING" in rep.codes()


def test_validator_requires_canonical_id_on_ordered_edges() -> None:
    from graqle.ontology.assurance import edge_id, validate_assurance_graph

    old, new = claim("old", None, *T_OLD), claim("new", "cid", *T_NEW)
    link = {
        "source": "new",
        "target": "old",
        "relationship": "RELATES_TO",
        "properties": {
            "id": edge_id("new", "old", "SUPERSEDES", "s"),
            "kind": "SUPERSEDES",
            "scope_key": "s",
            "asserted_at": T_NEW[1],
            "prov_event_id": "p",
        },
    }
    report = validate_assurance_graph({"nodes": [old, new], "links": [link]})
    assert any("canonical_id on the target" in v.message for v in report.violations)


# ── persister ─────────────────────────────────────────────────────────────────


class _NoConnector:
    database = "neo4j"

    def _get_driver(self) -> Any:  # pragma: no cover - must never be reached
        raise AssertionError("no write may happen without a keyring")


def test_persister_without_keyring_writes_nothing() -> None:
    with pytest.raises(KgPersistError, match="keyring"):
        Neo4jBatchPersister(_NoConnector()).persist_assurance_ops([claim_op("x", "c", *T_NEW)])


def test_constraint_rejection_is_classified_as_refused() -> None:
    class ConstraintError(Exception):
        code = "Neo.ClientError.Schema.ConstraintValidationFailed"

    assert _is_constraint_rejection(ConstraintError())
    assert not _is_constraint_rejection(TimeoutError())
    assert issubclass(AssuranceWriteRefusedError, KgPersistError)


# ── AssuranceOntologyConfig loader ────────────────────────────────────────────

_REQUIRED_ENV = {
    "GRAQLE_DAG_ENABLED": "true",
    "GRAQLE_DAG_CONFIG_SALT": SALT,
    "GRAQLE_DAG_CAP_VALUE": "0.31",
    "GRAQLE_DAG_HG05_POISONING_THRESHOLD": "0.61",
    "GRAQLE_DAG_HG07_MATERIALITY_THRESHOLD": "0.51",
    "GRAQLE_DAG_CALIBRATOR_VERSION": "cal-test-v0",
    "GRAQLE_DAG_TRAJECTORY_ESTIMATOR": "causal_baseline",
    "GRAQLE_DAG_MAX_RETRY_BUDGET": "3",
    "GRAQLE_DAG_CIRCUIT_BREAKER_WINDOW": "5",
    "GRAQLE_DAG_SIGNING_KEY_ID": "kid-test-2026",
    "GRAQLE_DAG_SIGNING_KEY_VERSION": "1",
    "GRAQLE_DAG_SCOPE_KEY_FIELDS_REF": "scope_fields_test",
    "GRAQLE_DAG_MERGE_PRIORITY_REF": "sdk_default",
}


@pytest.fixture
def dag_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from graqle.assurance.settings import reset_dag_settings_cache

    for key in list(os.environ):
        if key.upper().startswith("GRAQLE_DAG_"):
            monkeypatch.delenv(key, raising=False)
    for k, v in _REQUIRED_ENV.items():
        monkeypatch.setenv(k, v)
    secrets = tmp_path / "private.yaml"
    secrets.write_text("refs:\n  scope_fields_test: [f_alpha, f_beta]\n", encoding="utf-8")
    secrets.chmod(0o600)  # the loader refuses a group/world-readable private file on POSIX
    monkeypatch.setenv("GRAQLE_DAG_SECRETS_PATH", str(secrets))
    reset_dag_settings_cache()
    yield monkeypatch
    reset_dag_settings_cache()


def test_config_loader_fails_closed_without_ceiling_and_batch(dag_env: pytest.MonkeyPatch) -> None:
    from graqle.assurance.settings import ConfigurationError
    from graqle.ontology.assurance_config import load_assurance_ontology_config

    with pytest.raises(ConfigurationError) as ei:
        load_assurance_ontology_config()
    assert "GRAQLE_DAG_ASSURANCE_LABEL_CEILING" in str(ei.value)
    assert "GRAQLE_DAG_ASSURANCE_MIGRATION_BATCH" in str(ei.value)


def test_config_loader_resolves_private_refs(dag_env: pytest.MonkeyPatch) -> None:
    from graqle.ontology.assurance_config import load_assurance_ontology_config

    dag_env.setenv("GRAQLE_DAG_ASSURANCE_LABEL_CEILING", "100")
    dag_env.setenv("GRAQLE_DAG_ASSURANCE_MIGRATION_BATCH", "7")
    cfg = load_assurance_ontology_config()
    assert cfg.scope_key_fields == ("f_alpha", "f_beta")
    assert cfg.merge_priority is None
    assert "f_alpha" not in repr(cfg)  # TS-4 values never in a repr


def test_config_loader_unresolvable_ref_names_the_ref_only(dag_env: pytest.MonkeyPatch) -> None:
    from graqle.assurance.settings import ConfigurationError
    from graqle.ontology.assurance_config import load_assurance_ontology_config

    dag_env.setenv("GRAQLE_DAG_ASSURANCE_LABEL_CEILING", "100")
    dag_env.setenv("GRAQLE_DAG_ASSURANCE_MIGRATION_BATCH", "7")
    dag_env.setenv("GRAQLE_DAG_MERGE_PRIORITY_REF", "absent_ref")
    with pytest.raises(ConfigurationError, match="absent_ref"):
        load_assurance_ontology_config()


def test_config_loader_refuses_with_the_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from graqle.assurance.settings import ConfigurationError
    from graqle.ontology.assurance_config import load_assurance_ontology_config

    monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    with pytest.raises(ConfigurationError, match="GRAQLE_DAG_ENABLED"):
        load_assurance_ontology_config()


def test_flag_on_without_the_refs_is_a_startup_error(dag_env: pytest.MonkeyPatch) -> None:
    from graqle.assurance.settings import (
        ConfigurationError,
        load_dag_settings,
        reset_dag_settings_cache,
    )

    dag_env.delenv("GRAQLE_DAG_SCOPE_KEY_FIELDS_REF")
    reset_dag_settings_cache()
    with pytest.raises(ConfigurationError, match="GRAQLE_DAG_SCOPE_KEY_FIELDS_REF"):
        load_dag_settings()


def test_keyring_from_settings_fails_closed_without_salt(dag_env: pytest.MonkeyPatch) -> None:
    from graqle.assurance.integrity_keys import keyring_from_settings
    from graqle.assurance.settings import ConfigurationError, DagSettings

    kr = keyring_from_settings()
    assert kr.current_version == "v1" and kr.versions == ("v1",)
    dag_env.delenv("GRAQLE_DAG_CONFIG_SALT")
    dag_env.delenv("GRAQLE_DAG_ENABLED")
    with pytest.raises(ConfigurationError, match="GRAQLE_DAG_CONFIG_SALT"):
        keyring_from_settings(DagSettings())


# ── the AST gate ──────────────────────────────────────────────────────────────

_GATE = ROOT / "scripts" / "ci" / "assurance_write_path_gate.py"


def _gate(*roots: Path) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, str(_GATE)]
    for r in roots:
        args += ["--root", str(r)]
    return subprocess.run(args, capture_output=True, text=True, cwd=ROOT)


def test_gate_passes_on_the_package() -> None:
    res = _gate(ROOT / "graqle")
    assert res.returncode == 0, res.stdout


@pytest.mark.parametrize(
    "source",
    [
        'Q = "MATCH (n) SET n.valid_from = $v"',
        'Q = "MATCH (n) set n.asserted_at = $v"',
        "Q = f\"MATCH (a),(b) CREATE (a)-[:RELATES_TO {{kind: 'SUPERSEDES'}}]->(b)\"",
        'Q = "MATCH ()-[r:RELATES_TO]->() " + "SET r.kind = \'CORRECTS\'"',
        'A = "MERGE (a)-[r:RELATES_TO]->(b) ON CREATE SET r += $p"\n'
        'B = A + ", r.supersedes_in = b.id"',
        "Q = \"MATCH ()-[r:RELATES_TO {kind: 'SUPERSEDES'}]->() DELETE r\"",
        "from graqle.governance.tamper_evidence import _assurance_write",
    ],
)
def test_gate_fails_on_each_planted_violation(tmp_path: Path, source: str) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(source + "\n", encoding="utf-8")
    res = _gate(bad)
    assert res.returncode == 1, res.stdout
    assert "1 violation(s)" in res.stdout


def test_gate_ignores_docstrings_and_plain_mentions(tmp_path: Path) -> None:
    ok = tmp_path / "ok.py"
    ok.write_text(
        'def f():\n    """A raw driver can SET n.valid_from; the verifier detects it."""\n'
        'KINDS = ("SUPERSEDES", "CORRECTS")\n'
        'MSG = "SUPERSEDES needs source.valid_from > target.valid_from"\n',
        encoding="utf-8",
    )
    assert _gate(ok).returncode == 0


@pytest.mark.parametrize(
    "source",
    [
        # no write keyword at all, and no letter-A tricks: must stay clean
        "Q = \"MATCH ()-[r:RELATES_TO {kind: 'SUPERSEDES'}]->() RETURN r\"",
        # a write keyword with no ordered kind: must stay clean
        'Q = "MATCH (n) DETACH DELETE n"',
    ],
)
def test_gate_rules_need_both_the_write_and_the_kind(tmp_path: Path, source: str) -> None:
    ok = tmp_path / "ok.py"
    ok.write_text(source + "\n", encoding="utf-8")
    assert _gate(ok).returncode == 0


def test_gate_ordered_edge_rules_are_anchored() -> None:
    # A regex bug once replaced the anchor with a literal "A", which matched any
    # Cypher containing that letter. Pin the anchor itself.
    import importlib.util

    spec = importlib.util.spec_from_file_location("assurance_write_path_gate", _GATE)
    gate = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gate  # dataclasses resolve annotations via sys.modules
    try:
        spec.loader.exec_module(gate)  # type: ignore[union-attr]
    finally:
        sys.modules.pop(spec.name, None)
    for name, pat in gate.PATTERNS:
        if name.startswith("ordered-edge"):
            assert pat.pattern.startswith("\\A(?="), name


def test_gate_fails_closed_on_unparsable_files(tmp_path: Path) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    res = _gate(broken)
    assert res.returncode == 1 and "unparsable" in res.stdout
