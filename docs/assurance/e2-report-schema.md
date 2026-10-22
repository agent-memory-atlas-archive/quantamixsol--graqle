# E2 threshold-study report, schema `e2-report-1`

Produced by `graq assurance threshold-study --dataset <rows.jsonl> --out <dir> [--run-id <id>]`
(flag-guarded: requires `GRAQLE_DAG_ENABLED`). Implementation: `graqle/assurance/threshold_study.py`.

## Files

| File | Content |
|---|---|
| `e2-report-<run_id>.json` | Results (sorted keys). |
| `e2-report-<run_id>.runlog` | `key=value` lines: `schema`, `run_id`, `dataset_hash`, `results_sha256`, `sdk_version`, `config_version`, `seed`, `n_rows`, `arms_run`, `arms_skipped`. Hashes, counts and versions only; no settings values. |

`dataset_hash` is the SHA-256 of the dataset file bytes; `results_sha256` is the SHA-256 of the
`.json` file. Together with the results they form the numbers-to-artefacts triplet.

## Dataset card (JSONL, one object per line; unknown keys reject the file)

| Field | Type | Notes |
|---|---|---|
| `trace_id` | string | Unique in the file. |
| `entity_class` | `entity` / `relation` / `abstraction` / `decision` | |
| `domain` | string | |
| `confidence_scalar` | float in [0, 1] | The recorded scalar confidence. |
| `label` | integer 0 or 1 | 1 = the decision was correct. |
| `group_id` | string | Bootstrap cluster (groups are resampled, never rows). |
| `position` | integer >= 0 | Absolute checkpoint index (normalised positions are rejected). |
| `cv` | ConfidenceVector JSON, optional | Needed by the vector arm. |
| `arm_features` | object, optional keys | See below. |

`arm_features` keys, each optional; an arm whose key is missing on a row excludes that row (never zero-filled):

| Key | Used by |
|---|---|
| `governance_gate_score` (float in [0, 1]) | `baseline_governance_tiers` (confidence = 1 - score) |
| `drace_total` (float in [0, 1]) | `baseline_drace_grade` |
| `hard_gates_failed` (list of ids), `cap` (`{applied, value}`), `penalty_inputs` | `confidence_vector_<strategy>` via `project()` |
| `trajectory_reliability` (float in [0, 1]) | `trajectory_monitor` (CR-015; skipped until wired) |
| `causal` (CausalBaselineInput JSON) | `causal_baseline_combined` (needs causal parameters supplied to the API) |

## Report

Top level: `schema`, `run_id`, `dataset_hash`, `sdk_version`, `config_version`, `seed`, `method`,
`n_rows`, `arms`, `arm_notes`, `cross_class_threshold_finding`.

* `method` records the reporting constants used (band layout, bootstrap resamples and alpha,
  minimum rows per class and per band, material band gap). These are reporting parameters, not policy values.
* `arms[<arm>][<class>]` is either `{"skipped": <reason>, "n": <int>}` or a result with:
  `n`, `band_error_rates` (equal-width tenths: `lo`, `hi`, `n`, `error_rate`), `ece`, `brier`, `auroc`,
  `auprc` (each a grouped-bootstrap block: `point`, `ci_low`, `ci_high`, `n_valid`, `n_dropped`, `seed`,
  `n_groups`), `risk_coverage` (`aurc`, `e_aurc`, `n`) and `tc_ece` (`total`, `buckets`).
* Skip reasons: `insufficient_rows`, `metric_undefined` (for example a single-class label set),
  `arm_unavailable` (the arm's inputs were not supplied at all).
* `arm_notes[<arm>]` explains every skipped or placeholder arm.
* `cross_class_threshold_finding` lists arm/band cells where classes show materially different
  error rates for the same public band.

Arms: `baseline_governance_tiers`, `baseline_article14_placeholder` (status: placeholder),
`baseline_drace_grade`, `calibrated_scalar`, `confidence_vector_<strategy>`, `trajectory_monitor`,
`causal_baseline_combined`. Policy thresholds appear nowhere in the report; the vector arm uses
`project()` and only its score.
