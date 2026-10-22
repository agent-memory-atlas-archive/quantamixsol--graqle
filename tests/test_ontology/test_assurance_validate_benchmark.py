"""CR-016 PR-016d AC-15 (016d half): export + SHACL validate of a 200-node assurance subgraph.

Records the measured timing with a results JSON and a run-log id (numbers-to-artefacts).
The comparison against the private bound ``T_ASSURANCE_VALIDATE_P95_MS`` is opt-in: it runs
only when that environment variable is configured, otherwise it is skipped. The measured
number is recorded, never asserted against a public constant.
"""

from __future__ import annotations

import json
import os
import statistics
import time
import uuid
from pathlib import Path

import pytest

pytest.importorskip("pyshacl")

from graqle.governance.shacl.assurance_validator import AssuranceShaclValidator  # noqa: E402
from tests.test_ontology._assurance_fixtures import base, link  # noqa: E402
from tests.test_ontology.test_assurance_shapes import _graph  # noqa: E402

_NODE_COUNT = 200
_RUNS = 20
_BOUND_ENV = "T_ASSURANCE_VALIDATE_P95_MS"
_OUT_ENV = "GRAQLE_BENCH_OUT_DIR"


def _graph_200() -> dict:
    """Conformant graph of exactly 200 nodes: _graph() (3 nodes) plus supported claims."""
    g = _graph()
    for i in range(_NODE_COUNT - len(g["nodes"])):
        cid = f"bulk{i}"
        g["nodes"].append(
            base(
                cid,
                "Claim",
                claim_id=cid,
                canonical_id=f"c-{cid}",
                subject="s",
                predicate="p",
                object="o",
                confidence_vector_version="cv",
                valid_time="2026-07-01T00:00:00Z/",
                status="ACTIVE",
            )
        )
        g["links"].append(link(cid, "ev", "SUPPORTED_BY", prov=False))
    return g


def _p95(samples_ms: list[float]) -> float:
    ordered = sorted(samples_ms)
    return ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]


def _measure(validator: AssuranceShaclValidator, data: dict) -> list[float]:
    samples_ms: list[float] = []
    for _ in range(_RUNS):
        t0 = time.perf_counter()
        result = validator.validate_subgraph(data)
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
        assert result.conforms
    return samples_ms


def test_export_and_validate_200_nodes_recorded(tmp_path):
    data = _graph_200()
    assert len(data["nodes"]) == _NODE_COUNT
    validator = AssuranceShaclValidator()
    assert validator.validate_subgraph(data).conforms  # warm-up and correctness

    samples_ms = _measure(validator, data)
    run_log_id = f"ac15-016d-{uuid.uuid4()}"
    record = {
        "run_log_id": run_log_id,
        "ac": "AC-15",
        "pr": "PR-016d",
        "nodes": _NODE_COUNT,
        "runs": _RUNS,
        "samples_ms": samples_ms,
        "median_ms": statistics.median(samples_ms),
        "p95_ms": _p95(samples_ms),
        "bound_env": _BOUND_ENV,
        "bound_configured": bool(os.environ.get(_BOUND_ENV)),
    }
    out_dir = Path(os.environ.get(_OUT_ENV) or tmp_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{run_log_id}.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"AC-15 results JSON: {out} run_log_id={run_log_id} p95_ms={record['p95_ms']:.1f}")

    assert json.loads(out.read_text(encoding="utf-8"))["run_log_id"] == run_log_id


def test_p95_within_private_bound_when_configured():
    raw = os.environ.get(_BOUND_ENV)
    if not raw:
        pytest.skip(f"{_BOUND_ENV} not configured (private bound); timing recorded only")
    validator = AssuranceShaclValidator()
    data = _graph_200()
    validator.validate_subgraph(data)
    assert _p95(_measure(validator, data)) <= float(raw)
