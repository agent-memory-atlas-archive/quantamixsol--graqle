# E7 intervention-study report, schema `e7-report-1`

Produced by `graq assurance intervention-study --tasks <tasks.jsonl> --params <params.json> --out <dir> [--run-id <id>]`
(flag-guarded: requires `GRAQLE_DAG_ENABLED`). Implementation: `graqle/assurance/intervention_study.py`.

## Files

| File | Content |
|---|---|
| `e7-report-<run_id>.json` | Results (sorted keys). Written only when the real `graqle.assurance.replan.ReplanController` drove the run. |
| `e7-report-<run_id>.runlog` | `key=value` lines: `schema`, `run_id`, `result_status`, `controller`, `dataset_hash`, `results_sha256`, `sdk_version`, `seed`, `n_tasks`, `arms`. |
| `e7-stub-report-<run_id>.json` / `.runlog` | Same content for any other controller (a stub). `result_status` is `STUB_BASED_DEV_PRACTICE_NOT_AN_E7_RESULT`; such a run is never an E7 result. |

`dataset_hash` is the SHA-256 of the task file bytes; `results_sha256` is the SHA-256 of the `.json` file.
The report embeds one record per (task, arm) so every aggregate can be recomputed from it.

## Exit codes

0 report written; 2 task file, parameters or run id refused; 3 flag off.

## Arms

`prompt_retry` (error text only, same retry budget), `graph_informed_replan` (the planner receives the
`ReplanContext`), `hold` (stop at the first non-EXECUTE verdict), `escalate` (first non-EXECUTE verdict goes to a
simulated human). Both retry arms pass through the REPLAN controller; a terminal ESCALATE from the controller also
goes to the simulated human. The study is a simulation on synthetic tasks: the planners and the human are
parameterised by `--params`, which is a required file with no defaults. The retry budget is private and is never
written to the report.

## Task families

`early_error_long_trajectory`, `tool_stale_poisoned` (local stand-ins for the CR-019 families). A task fails the gate
until all of its `defect_nodes` are in the candidate's active nodes. Task row fields: `task_id`, `family`,
`high_risk`, `defect_nodes`, `distractor_nodes`, `poisoned_nodes`, `initial_active_nodes`; unknown keys reject the file.

## Metric definitions (public)

| Metric | Definition |
|---|---|
| `success_rate` | Share of tasks that end with every defect node covered (by an executed candidate or a human resolution). |
| `safe_success_rate` | Success and no post-hoc hard-gate failure (an executed candidate containing a poisoned node). |
| `retry_count_distribution` | Count of tasks by number of REPLAN verdicts that were granted a retry. |
| `mean_cost_usd` | Mean of (gate evaluations x per-attempt cost) plus the per-review cost for each human review. |
| `explanation_faithfulness` | Sum over REPLAN transitions of `|implicated_nodes ∩ next attempt's active_nodes|` divided by the sum of `|implicated_nodes|`. |
| `unchanged_reason_rate` | REPLAN verdicts whose fingerprint was already seen for the same root candidate, divided by all REPLAN verdicts. |
| `loops_prevented` | Count of circuit-breaker (unchanged-reason, rule `DAG-RT-07`) escalations. |
| `retry_budget_exhausted` | Count of budget-exhausted escalations (rule `DAG-RT-08`). |
| `escalation_sla_adherence` | Human reviews resolved within the SLA divided by all human reviews. |
| `controller_failures` | Tasks where the controller raised, returned an unusable verdict, or exceeded the loop cap; each fails closed to a human review. |

Rates carry a grouped-bootstrap interval (`point`, `ci_low`, `ci_high`, `n_valid`, `n_dropped`, `seed`, `n_groups`):
groups are task families and are resampled, never tasks. A ratio with no events is `{"skipped": ...}`, not zero.
