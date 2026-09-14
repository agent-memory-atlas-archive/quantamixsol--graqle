# DAG-2026 — Ground-truth addendum to the charter (CR-012 §0.3)

**Programme:** DAG-2026 (Decision Assurance Gate) | **CR:** CR-012 / PR-012a | **ADR:** ADR-RT-004 | **SDK baseline:** graqle 0.83.0 | **Re-verified against:** private tree `research-development-graqle` master `7c1cf8b5` on 2026-09-13 by the SDK team

The "Gracle Technical and Architectural Research Brief" (baseline 2026-09-11) §2 describes the current admission mechanism as "≥0.70 accept / 0.40–0.69 hold / <0.40 reject". That statement is **false for graqle 0.83.0**. This addendum is the binding correction (DAG-00 §2, ADR-RT-004). Every later DAG CR reads the SDK as described here, not as described in the charter.

| Charter §2 claim | v0.83.0 reality | Source |
|---|---|---|
| ≥0.70 accept / 0.40–0.69 hold / <0.40 reject | `review_threshold=0.70`, `block_threshold=0.90` are DANGER scores; tiers T1 / T2 / T3 / TS-BLOCK; **no hold band** | `core/governance.py:283-284, 793-930` |
| "confidence" gate | `gate_score = 0.5·risk_weight + 0.5·radius_weight`; not a confidence | `core/governance.py:742-750` |
| Article 14 human-review threshold | `0.75` placeholder, `threshold_status="placeholder"` always | `compliance/article_14_gate.py:64`, `settings.py:560` |
| "Five deterministic scoring dimensions" | DRACE D .25 / R .25 / A .20 / C .15 / E .15, fixed-weight linear, compensatory except `evaluate_constraint` cap | `intelligence/governance/drace.py:74-90, 266-288` |
| "Decision trail hashes" | R25-EU01 Merkle batch commitment + two narrow prev_hash chains; no per-event sequence numbers | `governance/tamper_evidence/*`, `compliance/eu_ai_act_latch.py:216`, `intelligence/governance/audit.py:68` |
| EXECUTE/REPLAN/HOLD/REJECT/ESCALATE as current outcomes | **proposed** DAG outcomes; current enum is `Decision{PASS,BLOCK,WARN}` | `governance/trace_schema.py:53` |
| Reason-code registry | none; `GovernanceDecision.reason` is free text ≤200 chars | `trace_schema.py:108` |
| `assurance.enabled` config key | does not exist; introduced by this CR as DERIVED from `GRAQLE_DAG_ENABLED` | this CR §3.3 |

## Verification notes (SDK team, 2026-09-13)

Every citation above was checked against the private master tree. Anchors that moved relative to the Research Team's 0.83.0 wheel inspection are recorded here so nobody re-targets them silently (brief §1 item 4). Nothing below changes a row of the table.

- `core/governance.py`: `GovernanceConfig` starts at :268 (CR §0.1 cites :270-309); `GateResult` at :317; `GovernanceBypassNode` at :351; the lazy RBAC `except ImportError` sites are :877, :906 and :937 (CR cites :861, which is now the `_rbac_check` call). `:283-284`, `:513`, `:681`, `:742-750`, `:825`, `:897` are unchanged.
- `config/settings.py`: `GraqleConfig.governance` at :811 (CR: :810); the `_reject_yaml_secrets(raw)` call is at :997 (CR: :1004, which is now the `model_validate` return); `_YAML_FORBIDDEN_SECRET_PATHS` at :1084; `def _reject_yaml_secrets` at :1089.
- `governance/trace_schema.py`: `schema_version: str = "2"` at :223 (CR: :220); `policy_version` at :224; `classify_schema_version` at :137 (CR: :139); `model_config = ConfigDict(extra="forbid")` at :186 (CR: :184).
- `compliance/eu_ai_act_latch.py`: `_signed_record` at :218 (CR: :216). `intelligence/governance/audit.py:68` unchanged.
- `governance/reliability_diagram.py:29` imports `graqle.governance.calibration`, which **exists in the source tree** (`CalibrationModel` at :73, `Calibrator` at :380; `calibration_store.py` exists too) and is present on the public `master` as well. The `ModuleNotFoundError` the Research Team observed is reproducible only from the **built wheel**: `pyproject.toml` `[tool.hatch.build.targets.wheel] exclude` carves out `graqle/governance/calibration.py` and `calibration_store.py` (WS-F trade-secret gate) while still shipping `reliability_diagram.py` and `cli/commands/calibrate_governance.py`. D3 is therefore a wheel-content defect (dead import shipped), not a missing module; PR-012c will fix it at the packaging/import boundary rather than by creating a second `CalibrationModel`. The Research Team is asked to amend CR-012 §0.1/§4.6 accordingly.
- `plugins/mcp_dev_server.py`: `_handle_ingest` :13108 and the raw-path block :13120-13135 unchanged; helper `_project_root_from_graph_file` :5216 unchanged. Two additional raw `Path(str(_raw)).resolve().parent` sites exist at :12487 and :12711 that the CR's 10-site list omits; PR-012c sweeps 12 sites.
- `pyproject.toml:60` already declares `pydantic-settings>=2.0` — CR-012 OQ-2 resolved: no new dependency.

## Operating the DAG flag (CR-012 / PR-012a, condition C3)

These notes apply only when `GRAQLE_DAG_ENABLED` is on. With the flag off (the default) none of them is reachable.

- **`GRAQLE_DAG_CONFIG_SALT` must come from a CSPRNG.** It keys the HMAC that commits to every private tuning value in `config_version`, so a guessable salt makes that commitment guessable. Generate it with `openssl rand -base64 48` (or `python -c "import secrets; print(secrets.token_urlsafe(48))"`), store it with the other deployment secrets, and never use a passphrase or any human-chosen string. The loader enforces a 32-byte floor and nothing else — length alone is not entropy. Rotating the salt changes every `config_version` computed afterwards; earlier fingerprints in run logs stay valid for the configuration they recorded but will not reproduce under the new salt, so rotate deliberately and record when. When no salt is configured the fingerprint is an explicitly unkeyed checksum tagged `keying="unkeyed_checksum_v1"`; CR-018's anchoring path refuses anything other than `deployment_salt_v1`.
- **Kubernetes secret mounts default to `0644` and will be refused.** The private-values file is opened with `O_NOFOLLOW` and rejected when its mode carries any group or world bit, so a `secret` volume mounted with the default permissions fails closed at startup with a `chmod 600` message naming the path. Set `defaultMode: 0400` on the volume (or project the file into a directory the service account alone can read). This is deliberate: the file holds TS-2/TS-3 values.
- **Windows residual.** `O_NOFOLLOW` and POSIX mode bits do not exist there, so symlink refusal is best effort and permissions are not checked — the loader logs a WARNING saying so. Restrict the file's ACL to the service account. A `realpath` comparison after open is a candidate for PR-012c, not a guarantee today.

## What this addendum does not change

`GovernanceMiddleware.check()` is untouched by CR-012. With `GRAQLE_DAG_ENABLED` unset, every `GateResult.to_dict()` is byte-identical to 0.83.0 (CR-012 AC-9 golden fixture, PR-012c).
