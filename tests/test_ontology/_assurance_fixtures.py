"""Shared builders for the CR-016 PR-016a tests. Values are test substitutes."""

from __future__ import annotations

from typing import Any

from graqle.ontology.assurance import edge_id

SALT = "test-substitute-salt-0123456789abcdef-XYZ"
SCOPE = "scope-substitute"
T0 = "2026-07-01T00:00:00Z"
T1 = "2026-09-01T00:00:00Z"

#: Non-inferential substitute scope fields (CR-016 §7 PR-016a TS focus).
SUBSTITUTE_SCOPE_FIELDS = ("f_alpha", "f_beta")


def base(node_id: str, cls: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": f"ASSURANCE_{cls.upper() if cls != 'ProvenanceEvent' else 'PROVENANCE_EVENT'}",
        "assurance_type": cls,
        "lifecycle_status": "ACTIVE",
        "valid_from": T0,
        "asserted_at": T1,
        "scope_key": SCOPE,
        **extra,
    }


def conformant_graph() -> dict[str, Any]:
    """One node of every class and one conformant edge of every kind."""
    nodes = [
        base(
            "ev",
            "Evidence",
            evidence_id="ev",
            source="eur-lex:substitute",
            captured_at=T1,
            canonical_hash="h",
            sensitivity="PUBLIC",
            authenticity_status="ATTESTED",
        ),
        base(
            "cl",
            "Claim",
            claim_id="cl",
            subject="s",
            predicate="p",
            object="o",
            confidence_vector_json="{}",
            confidence_vector_version="cv-sub",
            valid_time=f"{T0}/",
            status="ACTIVE",
        ),
        base(
            "cl2",
            "Claim",
            claim_id="cl2",
            subject="s2",
            predicate="p",
            object="o",
            confidence_vector_json="{}",
            confidence_vector_version="cv-sub",
            valid_time=f"{T0}/",
            status="ACTIVE",
        ),
        base(
            "ab",
            "Abstraction",
            abstraction_id="ab",
            method="m",
            inputs=["cl"],
            scope="x",
            confidence_vector_json="{}",
            confidence_vector_version="cv-sub",
            version=1,
        ),
        base(
            "in",
            "Instruction",
            instruction_id="in",
            authority="a",
            precedence=1,
            scope="x",
            effective_time=T0,
            status="ACTIVE",
        ),
        base(
            "po",
            "Policy",
            policy_id="po",
            version="1",
            jurisdiction="EU",
            conditions="{}",
            severity="HIGH",
            effective_time=T0,
        ),
        base(
            "de",
            "Decision",
            decision_id="de",
            alternatives=["a"],
            gate_outcome="HOLD",
            score_vector_json="{}",
            residual_risk=0.1,
            status="ACTIVE",
        ),
        base("ac", "Action", action_id="ac", tool="t", status="ACTIVE"),
        base(
            "ag",
            "Agent",
            agent_id="ag",
            agent_type="software",
            identity_assurance="IAL2",
            role="r",
            authorization_scope=["x"],
        ),
        base(
            "pe",
            "ProvenanceEvent",
            event_id="pe",
            event_type="CREATION",
            actor="ag",
            inputs=[],
            outputs=["ev"],
            canonical_hash="h",
            timestamp=T1,
        ),
    ]
    edges = [
        ("cl", "ev", "SUPPORTED_BY", False),
        ("ab", "cl", "DERIVED_FROM", False),
        ("cl", "cl2", "CONTRADICTS", False),
        ("cl2", "cl", "SUPERSEDES", True),
        ("cl2", "cl", "CORRECTS", True),
        ("cl", "cl2", "COEXISTS_WITH", True),
        ("de", "po", "GOVERNED_BY", False),
        ("pe", "ev", "USED", True),
        ("pe", "ev", "GENERATED", True),
        ("pe", "cl", "INVALIDATES", True),
    ]
    links = [link(s, t, k, prov=p) for s, t, k, p in edges]
    return {"nodes": nodes, "links": links}


def link(source: str, target: str, kind: str, *, prov: bool = True, **props: Any) -> dict[str, Any]:
    p: dict[str, Any] = {"kind": kind, "scope_key": SCOPE, "asserted_at": T1}
    if prov:
        p["prov_event_id"] = "pe"
    p.update(props)
    return {"source": source, "target": target, "relationship": "RELATES_TO", "properties": p}


def edge(source: str, target: str, kind: str, **kw: Any) -> dict[str, Any]:
    return {
        "id": edge_id(source, target, kind, SCOPE),
        "source_id": source,
        "target_id": target,
        "kind": kind,
        "scope_key": SCOPE,
        "asserted_at": T1,
        **kw,
    }
