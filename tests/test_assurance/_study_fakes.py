"""Synthetic datasets for the threshold-study tests. Fixed seeds, no real data."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from graqle.assurance.confidence_vector import EntityClass

from ._proj_fakes import vector

ROWS_PER_CLASS = 2000


def synthetic_rows(
    n_per_class: int = ROWS_PER_CLASS,
    *,
    with_drace: bool = True,
    with_vector: bool = False,
    seed: int = 7,
) -> list[dict]:
    """Rows whose true correctness equals the score for every class except DECISION.

    DECISION is made over-confident (true rate = score cubed), so the same band
    has a materially higher error rate there: the cross-class finding must fire.
    """
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    for cls in EntityClass:
        for i in range(n_per_class):
            score = float(rng.uniform(0.02, 0.98))
            p_true = score**3 if cls is EntityClass.DECISION else score
            features: dict = {"governance_gate_score": float(min(1.0, max(0.0, 1.0 - score)))}
            if with_drace:
                features["drace_total"] = score
            row = {
                "trace_id": f"{cls.value}-{i}",
                "entity_class": cls.value,
                "domain": "synthetic",
                "confidence_scalar": score,
                "label": int(rng.uniform() < p_true),
                "group_id": f"g{i // 5}",
                "position": i % 12,
                "arm_features": features,
            }
            if with_vector:
                row["cv"] = vector(entity_class=cls, default=score).model_dump(mode="json")
                features.update(
                    hard_gates_failed=[] if i % 10 else ["HG-01"],
                    cap={"applied": False, "value": 1.0},
                    penalty_inputs={
                        "unresolved_contradictions": 0,
                        "staleness": 0.0,
                        "dependency_penalty": 0.0,
                    },
                )
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path
