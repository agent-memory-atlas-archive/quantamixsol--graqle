"""CR-016 AC-2, AC-3, AC-16: mounts, collision refusal, SUPERSEDES untouched, determinism."""

from __future__ import annotations

import dataclasses

import pytest

import graqle.ontology.schema as schema
from graqle.assurance.settings import DagSettings
from graqle.ontology.assurance import (
    ASSURANCE_HIERARCHY,
    ASSURANCE_NODE_SHAPES,
    AssuranceRegistrationError,
    register_assurance_ontology,
)
from graqle.ontology.upper import UpperOntology

from ._assurance_fixtures import SALT

SETTINGS = DagSettings(config_salt=SALT)


@pytest.fixture(autouse=True)
def _restore_global_shapes():
    """Registration mutates the module-level shape registries; restore them per test."""
    nodes, edges = dict(schema.NODE_SHAPES), dict(schema.EDGE_SHAPES)
    yield
    schema.NODE_SHAPES.clear()
    schema.NODE_SHAPES.update(nodes)
    schema.EDGE_SHAPES.clear()
    schema.EDGE_SHAPES.update(edges)


@pytest.fixture
def flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAQLE_DAG_ENABLED", "true")


def test_flag_off_skips_and_mutates_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAQLE_DAG_ENABLED", raising=False)
    upper = UpperOntology()
    before = (dict(upper.hierarchy), dict(schema.NODE_SHAPES), dict(schema.EDGE_SHAPES))
    record = register_assurance_ontology(upper)
    assert record.skipped
    assert (dict(upper.hierarchy), dict(schema.NODE_SHAPES), dict(schema.EDGE_SHAPES)) == before


@pytest.mark.usefixtures("flag_on")
def test_all_nine_mounts_resolve() -> None:  # AC-2
    upper = UpperOntology()
    register_assurance_ontology(upper, settings=SETTINGS)
    for key, parent in ASSURANCE_HIERARCHY.items():
        assert upper.is_subtype_of(key, parent), key
        assert upper.is_subtype_of(key, "Thing")
    assert upper.is_subtype_of("ASSURANCE_CLAIM", "Artifact")
    assert not upper.is_subtype_of("ASSURANCE_DECISION", "Artifact")


@pytest.mark.usefixtures("flag_on")
def test_mount_collision_raises() -> None:  # AC-2
    upper = UpperOntology({"ASSURANCE_CLAIM": "Cognitive"})
    with pytest.raises(AssuranceRegistrationError, match="already mounted"):
        register_assurance_ontology(upper, settings=SETTINGS)


@pytest.mark.usefixtures("flag_on")
def test_node_shape_collision_raises_and_is_never_overwritten() -> None:
    foreign = schema.NodeShape(node_type="ASSURANCE_EVIDENCE", description="someone else's")
    schema.register_node_shape(foreign)
    with pytest.raises(AssuranceRegistrationError, match="already exists"):
        register_assurance_ontology(UpperOntology(), settings=SETTINGS)
    assert schema.NODE_SHAPES["ASSURANCE_EVIDENCE"] is foreign


@pytest.mark.usefixtures("flag_on")
def test_non_strict_skips_foreign_shapes_without_overwriting() -> None:
    foreign = schema.NodeShape(node_type="ASSURANCE_EVIDENCE", description="someone else's")
    schema.register_node_shape(foreign)
    record = register_assurance_ontology(UpperOntology(), strict=False, settings=SETTINGS)
    assert record.skipped_shapes == ("ASSURANCE_EVIDENCE",)
    assert schema.NODE_SHAPES["ASSURANCE_EVIDENCE"] is foreign


@pytest.mark.usefixtures("flag_on")
def test_registration_is_idempotent() -> None:
    upper = UpperOntology()
    first = register_assurance_ontology(upper, settings=SETTINGS)
    second = register_assurance_ontology(upper, settings=SETTINGS)
    assert first == second


@pytest.mark.usefixtures("flag_on")
def test_paper_supersedes_edge_shape_is_untouched() -> None:  # AC-3
    before = schema.EDGE_SHAPES["SUPERSEDES"]
    snapshot = dataclasses.asdict(before)
    register_assurance_ontology(UpperOntology(), settings=SETTINGS)
    assert schema.EDGE_SHAPES["SUPERSEDES"] is before
    assert dataclasses.asdict(schema.EDGE_SHAPES["SUPERSEDES"]) == snapshot


@pytest.mark.usefixtures("flag_on")
def test_relates_to_carrier_shape_registered_once() -> None:
    register_assurance_ontology(UpperOntology(), settings=SETTINGS)
    shape = schema.EDGE_SHAPES["RELATES_TO"]
    assert shape.allow_any_source and shape.allow_any_target
    assert {s.node_type for s in ASSURANCE_NODE_SHAPES} <= set(schema.NODE_SHAPES)


@pytest.mark.usefixtures("flag_on")
def test_determinism_record_is_complete() -> None:  # AC-16
    record = register_assurance_ontology(UpperOntology(), settings=SETTINGS)
    assert record.rule_id == "CR016.register"
    assert record.rule_version
    assert record.inputs_hash and record.inputs_hash.startswith("sha256:")
    assert record.config_version and record.config_version.startswith("sha256:")
    other = DagSettings(enabled=False, config_salt=SALT, hg05_poisoning_threshold=0.61)
    assert register_assurance_ontology(UpperOntology(), settings=other).config_version != (
        record.config_version
    )
