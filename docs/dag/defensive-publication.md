# Ordered Independent Hard Gates with Non-Compensatory Evaluation and a Critical-Failure Cap for Governing Autonomous Agent Actions

**Type:** Defensive publication (design disclosure)
**Publisher:** Quantamix Solutions B.V.
**Authors:** Harish Kumar (Quantamix Solutions B.V.)
**Drafted:** 2026-09-27
**Public disclosure date:** _the date this document is first posted publicly (GitHub commit timestamp); arXiv identifier added when assigned_
**Related software:** `graqle` on PyPI, repository `quantamixsol/graqle`

---

## 0. What this document is, and what it is not

This document puts a design into the public domain, so that it is prior art against any later patent claim on
the design or an obvious variant of it. It is not a patent application. It claims no novelty and asserts no
rights. Anyone may implement the design it describes.

**This is a design disclosure. It has not yet been reduced to practice.** Section 2 states exactly what
software exists today. Nothing in Sections 3 to 6 should be read as a description of shipped behaviour
unless Section 2 lists it.

## 1. Summary

An automated agent that proposes an action (a tool call, a code change, a deployment) is governed by an
**ordered set of independent boolean gates**. Each gate tests one disqualifying condition and returns PASS
or FAIL. Evaluation is **non-compensatory**: a FAIL on any gate cannot be offset by a high score anywhere
else, and when any gate fails the action cannot be executed. Every gate is always evaluated, even after an
earlier FAIL, so the record of reasons is complete. The first failing gate in the fixed order is recorded as
the decisive rule. When any gate fails, a **critical-failure cap** bounds any downstream numeric aggregate
from above by a private constant, and no later stage may raise it back. Every gate is **fail-closed**: a
missing input, an exception, or a timeout is a FAIL, never a PASS. Every gate emits a **determinism
record**: a hash of the canonical inputs it read, its rule version and a commitment to the configuration.
With that record the evaluation can be replayed without revealing the configured values.

## 2. Implementation status (as of the drafting date)

### 2.1 What is public today

The **verdict schema** that this design produces is published. No gate, cap or typology logic is published.
The schema first appeared in `graqle` 0.84.1 (tag `v0.84.1`, commit `52e61661`) and is present in 0.85.0
(tag `v0.85.0`, commit `b861a7ed`), which is the current PyPI release.

| File (in the 0.85.0 release) | What it contains |
|---|---|
| `graqle/assurance/verdict.py` | `GateVerdict`, `HardGateResultRef`, `DeterminismRecord`, `GateVerdictRef`. A validator rejects outcome `EXECUTE` whenever any hard-gate result has `passed = False` or `evaluation_errors` is non-empty. A validator rejects a hard-gate result that carries an `error` and `passed = True`. The verdict carries a boolean `cap_applied`, never a cap value. |
| `graqle/assurance/outcomes.py` | The five outcomes `EXECUTE`, `REPLAN`, `HOLD`, `REJECT`, `ESCALATE`. |
| `graqle/assurance/settings.py` | `DagSettings`, which declares the configuration **names** used below: `cap_value`, `hg05_poisoning_threshold`, `hg07_materiality_threshold`, `hg03_impact_tier_min`, `rbac_timeout_ms`, `gate_timeout_ms`. The cap and the two score thresholds have no default and are required when the feature is enabled. |
| `graqle/assurance/reason_codes.py` | The reason-code format, which reserves namespaces `DAG-HG01` … `DAG-HG07`. The public seed of registered codes is **empty**. |

The feature flag `GRAQLE_DAG_ENABLED` is off unless it is set to a recognised true value. With it off, none
of the above changes the SDK's behaviour.

### 2.2 What does not exist yet

- No hard gate, gate registry, critical-failure cap, control typology, sensitivity report or property-test
  suite has been implemented, in the public or any other released build.
- Gates HG-02 and HG-04 depend on components that do not exist yet: evidence-invalidation tracking and
  argument binding. The design says both **fail closed** until those components exist.
- No experiment has been run. This document makes **no claim** about effectiveness, false-block rates,
  latency or any other measured property.

## 3. Problem

Many governance systems combine several risk or quality signals into one weighted score and compare that
score with a threshold. Such a **compensatory** aggregate can be gamed. High scores on easy dimensions can
hide a single disqualifying condition, for example:

- no applicable policy
- evidence that has been invalidated
- no provenance for a high-impact action
- arguments that changed after approval
- a poisoned source
- an unauthorised actor
- an unresolved material contradiction

A system that must never execute an action in any of these states needs checks that no other score can
outweigh. It also needs a guarantee that no later numeric stage can quietly undo those checks.

## 4. Design

### 4.1 Definitions

```
ctx        := the gate context: all inputs to one evaluation, immutable for that evaluation
G          := the ordered tuple (HG-01, HG-02, HG-03, HG-04, HG-05, HG-06, HG-07)
g_i(ctx)   ∈ {PASS, FAIL}        result of hard gate i; any exception ⇒ FAIL with an error recorded
H(ctx)     := conjunction of g_i(ctx) over all gates in G       the all-pass predicate
A(ctx)     ∈ [0, 1]              any downstream compensatory aggregate (a weighted score, a projection)
CAP_VALUE  ∈ (0, 1)              a private operator-configured constant; symbol only
outcome    ∈ {EXECUTE, REPLAN, HOLD, REJECT, ESCALATE}
```

Threshold symbols below are names. Their values belong to the operator's configuration and are not part of
this disclosure (Section 7).

### 4.2 The gates

Each gate is a boolean predicate. It **fails** when the stated condition is true.

| Gate | Condition tested | FAIL when |
|---|---|---|
| HG-01 | Mandatory policy | `policy_missing ∨ policy_expired(now) ∨ policy_unresolved ∨ policy_violated`, where the policy is retrieved **by governance scope, not by text similarity**. `policy_expired := valid_until ≠ ∅ ∧ valid_until < now`. `policy_unresolved := ∃ a contradiction edge from the policy to another policy with no explicit co-existence ruling`. `policy_violated := the caller-supplied set of policy violations is non-empty`. |
| HG-02 | Invalidated evidence | Some dependency node of the action is marked invalidated and has not been recomputed. |
| HG-03 | Provenance for high impact | `impact_tier(risk_level) ≥ HG03_IMPACT_TIER_MIN ∧ the set of provenance event identifiers is empty`. An unknown or missing risk level is treated as the highest tier. |
| HG-04 | Argument binding | `approved_args_hash is absent ∨ approved_args_algorithm ≠ actual_args_algorithm ∨ approved_args_hash ≠ actual_args_hash`. The hashes are compared in constant time. |
| HG-05 | Poisoning | `poisoning_severity ≥ HG05_POISONING_THRESHOLD`, or the severity is absent. Severity is a caller-supplied score in [0, 1]. |
| HG-06 | Actor authorisation | The actor is not authorised for the required approval tier, **or** the authorisation service does not answer within `RBAC_TIMEOUT_MS`, **or** it raises an exception, **or** it cannot be loaded. |
| HG-07 | Material contradiction | Some pair of contradicting items has `materiality ≥ HG07_MATERIALITY_THRESHOLD` and no explicit co-existence ruling, or its materiality is absent. Materiality is a caller-supplied score in [0, 1]. |

Every gate is **independent**. It reads only its own slice of `ctx`, takes no other gate's result as input,
and performs no graph traversal. The caller materialises every slice into `ctx` beforehand.

### 4.3 Evaluation procedure

```
function EVALUATE(ctx, settings):
    require registry contains every gate id in G                   # otherwise: configuration error, nothing runs
    require every setting marked required-when-enabled is present  # otherwise: configuration error

    results := []
    for gate in G (fixed order):                                   # NO short-circuit
        start deadline(settings.GATE_TIMEOUT_MS)
        try:
            r := gate.evaluate(ctx.slice_for(gate), settings)
        except any error or deadline exceeded:
            r := FAIL with error string and reason code DAG-RP-EVALUATION_ERROR
        r.record := DETERMINISM_RECORD(gate, ctx, settings, r)
        results.append(r)

    all_pass       := every r in results has r.passed
    decisive_rule  := id of the first r in results (G order) with not r.passed, else none
    reason_codes   := de-duplicated union of reason codes from failed results, in G order
    return results, all_pass, decisive_rule, reason_codes

function APPLY_CAP(aggregate, results, settings):
    if aggregate is not a number within [0, 1]:  aggregate := lower bound of the range   # malformed ⇒ worst, fail-closed
    if every r in results has r.passed:
        return (value = aggregate, cap_applied = false)
    return (value = min(aggregate, settings.CAP_VALUE),
            cap_applied = true,
            decisive_rule = first failed id in G order,
            reason_codes = failed codes + DAG-RP-CAP_APPLIED)
    # the returned object never contains CAP_VALUE itself

function DECIDE(results, capped, downstream_stage):
    outcome := downstream_stage(capped.value, ...)                 # any later scoring or routing
    if not all_pass(results) and outcome = EXECUTE:
        reject as a schema error                                   # enforced by the verdict validator
    return outcome
```

### 4.4 Non-compensatory invariants

```
INV-HG-1  H(ctx) = FAIL  ⇒  outcome ≠ EXECUTE
INV-HG-2  every gate is evaluated on every evaluation; decisive_rule = first FAIL in G order
INV-HG-3  g_i(ctx) = g_i(ctx') whenever gate i's inputs hash, rule version and configuration commitment are equal
INV-HG-4  a missing input, a dependency error or a timeout ⇒ g_i = FAIL with the error recorded
```

The ordering of `G` makes the decisive rule deterministic. It does not create precedence between gates:
each gate can block on its own, and none can un-block another.

### 4.5 Critical-failure cap

```
cap(A, H) := A                    if H = PASS
          := min(A, CAP_VALUE)    if H = FAIL
```

Properties:

- **Idempotent:** `cap(cap(A,H),H) = cap(A,H)`
- **Monotone:** `A ≤ A' ⇒ cap(A,H) ≤ cap(A',H)`
- **Bounded:** `H = FAIL ⇒ cap(A,H) ≤ CAP_VALUE`, which is strictly below the top of the range
- **No lift:** while `H = FAIL`, no later stage may replace the capped value with one greater than `CAP_VALUE`.
  Later stages consume only the capped value.

The cap never chooses an outcome by itself. It bounds the aggregate and sets `cap_applied`. Outcome routing
is a separate stage, and that stage is still bound by INV-HG-1. The cap value never appears in any result
object, serialisation, log record or trace.

### 4.6 Fail-closed conditions, enumerated

Each of these makes the affected gate FAIL. There is no fallback path to PASS:

- A required context field is absent.
- A field is present but cannot be parsed or validated (for example, a score outside [0, 1], or not a number).
- A dependency (policy store, authorisation service, invalidation tracker, binding source) times out.
- A dependency raises an exception or cannot be imported or loaded.
- The gate's own evaluation raises an exception or exceeds its deadline.
- A required configuration value is absent while the feature is enabled. This one refuses the whole
  evaluation before any gate runs.

### 4.7 Determinism record

Each gate result carries:

```
inputs_hash          := "sha256:" + SHA-256( RFC 8785 canonical JSON of project_i(ctx) )
project_i(ctx)       := only the context fields that gate i's predicate reads; list-valued fields are
                        canonicalised so that permuting them does not change the hash;
                        configured threshold values are never part of the projection
rule_id, rule_version
config_version       := a keyed commitment over the configuration (never the values themselves)
decisive_conditions  := names of the atomic predicates that were true, e.g. ["policy_expired"]; names only
evaluated_at
error                := null, or an error string (a result with an error cannot be PASS)
```

Replaying an evaluation with an equal `inputs_hash`, `rule_version` and `config_version` must give an equal
result.

### 4.8 Control typology

Every control in the system has exactly one type from a closed set:

| Type | May change the outcome | May be offset by other scores | Evaluated before any aggregate |
|---|---|---|---|
| `DESCRIPTIVE` | no | n/a | n/a |
| `COMPENSATORY` | yes, through its weight in an aggregate | yes | no |
| `THRESHOLD` | yes | n/a | n/a |
| `HARD` | yes | **no** | **yes** |
| `CAP` | bounds an aggregate only | **no** | applied after hard gates, before outcome routing |

`HARD` and `COMPENSATORY` are disjoint. An existing weighted score in a system (for example, a
multi-pillar quality score) is classified `DESCRIPTIVE` and consumed unchanged as one input. It is not
rewritten into a gate.

### 4.9 Required properties

| Property | Statement |
|---|---|
| Monotone | For a scalar input where larger is worse, if a value makes the gate FAIL, every larger value also makes it FAIL. |
| Boundary | Comparisons use `≥`. `s = τ ⇒ FAIL`; `s = τ − ε ⇒ PASS` for a small positive `ε`. The result is stable when values round-trip between single and double precision. |
| Missing data | Any required field that is absent gives FAIL with an error, never PASS. |
| Correlated evidence | Provenance counts and contradiction materiality are computed over **distinct source identities**. Sources are de-duplicated by a canonical source identifier, so `k` copies of one source count as one source. |
| Adversarial duplication | Duplicating a provenance or support source any number of times never flips a gate from FAIL to PASS. |
| Permutation | Permuting any list-valued context field changes neither the inputs hash nor the result. |
| Exception isolation | An exception in one gate gives FAIL for that gate. Every other gate is still evaluated. |

## 5. Variants (also disclosed)

Each of the following variants is disclosed, alone and in any combination:

- **Gate set:** any subset or superset of the gates above. Examples include gates that test licence
  compliance, data residency, cost or budget exhaustion, rate limits, human-approval presence, model or
  version pinning, sandbox escape indicators, credential exposure, and output-schema validity. Any
  condition that can be expressed as a boolean predicate over a context slice qualifies.
- **Order:** any fixed total order over the gates, for example by cost of evaluation, by severity, or
  alphabetically by id. An order used only to choose the decisive rule is one variant. An order combined
  with short-circuit evaluation, where only the first FAIL is reported, is another.
- **Evaluation strategy:** sequential, concurrent or batched. Gate deadlines can be per gate or apply to
  the whole evaluation.
- **Result domain:** PASS/FAIL; or PASS/FAIL with a severity (for example FAIL versus CRITICAL, where
  CRITICAL routes to rejection); or a three-valued domain with an explicit UNKNOWN that is treated as FAIL.
- **Cap form:** `min(A, c)` with a constant `c`. Also: a cap that depends on how many gates failed, or which
  ones; a cap applied to a vector of scores component by component; a cap implemented by replacing the
  aggregate with a fixed sentinel; a cap realised as a hard outcome ceiling instead of a numeric bound.
- **Where the cap applies:** to a single aggregate, to every aggregate downstream of the gates, or to a
  projected or forecast score as well as the current one.
- **Outcome routing:** any mapping from (gate results, capped aggregate, retry state) to outcomes that
  never yields EXECUTE when a gate failed. This includes mappings that choose REPLAN for failures that can
  be resolved and ESCALATE or REJECT for failures that cannot.
- **Determinism record:** any hash function in place of SHA-256; any canonical serialisation in place of
  RFC 8785; a projection by allowlist or by denylist; a configuration commitment made by HMAC, by a salted
  hash or by a signature.
- **Source de-duplication key:** a canonical source identifier; a URI; a content digest; or a tuple of
  identifier and content digest.
- **Deployment point:** before a tool call, before a code write, before a deployment step, before a
  memory or knowledge-graph write, or before a message leaves a multi-agent system.
- **Actor:** a single agent, a multi-agent system, or a human-in-the-loop pipeline where the "action" is a
  proposed human decision.

## 6. Relation to known techniques

Non-compensatory decision rules are well known in multi-criteria decision analysis: conjunctive rules,
where every criterion must meet its cut-off, and lexicographic rules. Single-threshold blocking gates, such
as a CI step that fails below a configured score, are also common. This document does not claim any of
those as new.

What this document places on the public record is their specific combination applied to governing the
actions of autonomous software agents:

- an ordered set of independent boolean gates, each fail-closed, all evaluated without short-circuit
- an outcome constraint that makes execution impossible after any gate failure, enforced at the level of
  the verdict schema
- a critical-failure cap that bounds every downstream aggregate and forbids later stages from lifting it
- a per-gate determinism record that makes each decision replayable without revealing configured values
- a closed control typology under which each control is labelled by what it may and may not do

## 7. Deliberately not disclosed

The following are operator configuration or implementation detail and are **not** part of this disclosure.
The design as described works with any value in the declared ranges.

- The value of `CAP_VALUE` and of every gate threshold (`HG03_IMPACT_TIER_MIN` as deployed,
  `HG05_POISONING_THRESHOLD`, `HG07_MATERIALITY_THRESHOLD`), and the deployed values of the timeouts
- How materiality and poisoning severity are estimated. The design only consumes them as scores in [0, 1].
- The reasoning behind any particular gate order beyond "fixed, for determinism"
- The reasoning behind any particular control's typology assignment

## 8. Where each factual statement comes from

| Statement | Artefact |
|---|---|
| 0.85.0 is the current PyPI release; tag `v0.85.0` → commit `b861a7ed` | PyPI project `graqle`; tag `v0.85.0` in `quantamixsol/graqle` |
| The verdict schema first appeared in 0.84.1; tag `v0.84.1` → commit `52e61661` | tag `v0.84.1` in `quantamixsol/graqle`, `graqle/assurance/verdict.py` |
| EXECUTE is impossible with a failed hard gate or with evaluation errors | `graqle/assurance/verdict.py`, `GateVerdict._consistency` |
| A hard-gate result with an error cannot pass | `graqle/assurance/verdict.py`, `HardGateResultRef._error_implies_fail` |
| The verdict records whether the cap applied (`cap_applied: bool`) and has no field for the cap value | `graqle/assurance/verdict.py`, `GateVerdict`, `GateVerdictRef` |
| Five outcomes | `graqle/assurance/outcomes.py`, `GateOutcome` |
| Seven gate namespaces `HG01`–`HG07` | `graqle/assurance/reason_codes.py`, `CODE_PATTERN` |
| The public reason-code seed is empty | `graqle/assurance/reason_codes.py`, `_SEED` |
| Configuration names; cap in (0, 1); score thresholds in (0, 1]; no default for cap or thresholds | `graqle/assurance/settings.py`, `DagSettings`, `REQUIRED_WHEN_ENABLED` |
| Scores bounded in [0, 1] | `graqle/assurance/verdict.py` field bounds |
| Inputs hash uses RFC 8785 canonical bytes and SHA-256; `config_version` is a keyed commitment | `graqle/assurance/verdict.py`, `DeterminismRecord` docstring |
| Flag off by default; a recognised true value is required to enable | `graqle/assurance/settings.py`, `is_dag_enabled` |

Apart from identifiers (gate ids, version numbers, commit hashes, the RFC and hash-algorithm names), dates,
and the range bounds 0 and 1, no number appears in this document.
