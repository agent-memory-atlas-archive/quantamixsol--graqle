# Research

GraQle is built on a research programme, not a feature backlog. This page says what we are
investigating, what we have proven, and — most importantly — **what we have not**.

We publish this because the difference between a shipped mechanism and a research direction is
exactly the thing most AI infrastructure documentation blurs. If a claim on this page is labelled
*research*, it means you should not buy on it yet.

## How to read the status labels

| Label | What it means |
|---|---|
| **Shipped** | Implemented, tested, and you can exercise it today |
| **Architecture thesis** | The system is built as though this is true; the benchmark that would demonstrate it has not reported |
| **Research** | An open question with a hypothesis and a stop condition. It may fail |
| **Not claimed** | We are deliberately not asserting this, and you should be sceptical of anyone who does |

A programme can be rejected. Every one below has a stop condition, and a result that contradicts
our own thesis is a valid outcome we will report rather than quietly requalify.

---

## What is shipped, and what that entitles you to conclude

| Capability | Status | What you can verify yourself |
|---|---|---|
| Architecture-aware reasoning over a persistent graph | **Shipped** | `graq scan`, then ask a cross-file impact question |
| Model-agnostic operation | **Shipped** (compatibility) | 13 backends plus custom; swap and re-run |
| Persistent lessons across sessions | **Shipped** | Teach a lesson; start a new session; it recalls |
| Confidence and evidence on answers | **Shipped** | Every answer carries confidence and an evidence trail |
| Fail-visible retrieval | **Shipped (0.84.1)** | A missing vector index now raises a typed error instead of silently degrading |
| Governed write paths, decision attestation | **Shipped** | Write gates, runtime attestation, cryptographic audit trail |

**Model-agnostic operation is compatibility, not yet continuity.** The stronger claim — that
evidence selection and gate state survive a model swap — is Programme H below, and it is
unproven. We are careful about this distinction because it is the one most worth getting right.

---

## The Decision Assurance Gate

A confidence score is a single number, and a single number cannot express *why* something should
not proceed. The Decision Assurance Gate replaces scalar gating with an explicit verdict:

```
EXECUTE · REPLAN · HOLD · REJECT · ESCALATE
```

driven by non-compensatory hard gates (a critical failure cannot be outvoted by strong scores
elsewhere), a multi-dimension confidence vector, and a hash-chained provenance record.

**Status: foundation shipped in 0.84.1, behind `GRAQLE_DAG_ENABLED` (off by default).** The
vocabulary, typed settings and verdict schema exist. Hard gates, the confidence vector, the
trajectory monitor and the provenance chain are specified and not yet built. The flag stays off
until the evaluation suite passes with recorded results.

---

## Open research programmes

### A · Trusted state, not memory · *Architecture thesis*

Memory can faithfully preserve something wrong or superseded. Trusted state requires knowing
which claim is authoritative, when it was valid, and what replaced it.

**Hypothesis:** a graph carrying authority, temporal validity and contradiction resolution answers
"what is true *now*" more accurately than retrieval over the same corpus.
**Stop condition:** if it does not beat a retrieval baseline on current-answer accuracy, the
trusted-state framing is withdrawn from public claims.

### B · Evidence independence · *Research*

Three agents agreeing is not three pieces of evidence if they share a model family, a prompt
template, or a source. Confidence must discount correlated failure.

**Status:** the correlation discount is specified — agreement between generators sharing a model
family or prompt template is counted once, not three times. **Calibration has not reported.**
**Boundary we hold ourselves to:** shared identity proves correlation; *different* identity does
**not** prove independence. Two models trained on overlapping corpora remain correlated in ways
we cannot currently detect. So this measures *detected* independence, and we will not describe it
otherwise.

### C · Capability provenance and skill poisoning · *Research*

Agent skills and plugins are a software supply chain. The same trust logic we apply to facts
should apply to tools *before* they execute.

**Hypothesis:** capability manifests plus provenance gating catch untrusted skills at an
acceptable false-positive rate. **Not started.**

### D · Agent identity and authority · *Research*

An agent may swap models and keep its organisational role. Authority should expire, and revoking
a parent's permission must reach its subagents. **Not started**, with a deliberate boundary: we
are not rebuilding identity management, only the authority graph over it.

### E · Minimal sufficient context · *Research*

More context is not more intelligence. How small can the activated subgraph be while still
answering correctly? **Not started.**

### F · Change intelligence · *Research*

AI makes code cheap to produce, so validation becomes the bottleneck. Can review cost stay
sublinear as generated change volume rises an order of magnitude? **Not started.**

### G · Decision-grade intelligence · *Research*

Moving from answering a question to structuring the decision: options, assumptions,
reversibility, and what would change the answer. **Not started.**

### H · Model portability · *Research · highest near-term priority*

**Hypothesis:** for a fixed graph and question set, the evidence an answer rests on — activated
nodes, recalled lessons, evidence pointers, gate outcome — is substantially invariant across
model backends, while the answer's wording is not.

Measured against a within-backend baseline, because cross-model agreement means nothing without
knowing how much a single model varies against itself. One of the three backends is deliberately
a small local model: two frontier models agreeing would prove very little.

**Stop condition:** if cross-backend agreement is no better than within-backend variance, we
narrow the README to compatibility and say so here.

### I · Safe institutional learning · *Research*

One success is not a universal rule. Lessons need promotion states, expiry, and detection of
poisoned memory. **Not started.**

---

## What we do not claim

- **Self-improving organisational intelligence.** Not claimed. Learning safety and promotion rules
  are unproven, and the phrase oversells what any current system does.
- **Trusted organisational state as a delivered guarantee.** It is an architecture thesis until
  Programme A's benchmark reports.
- **Evidence-independent confidence.** Specified, not calibrated.
- **That more agents produce better answers.** Multi-agent debate is a reasoning mechanism, not a
  proof of truth. We removed language implying otherwise.
- **DAG-governed autonomous execution.** Not claimed until replay and rollback are implemented and
  demonstrated.

---

## How we work

Rules we adopted after getting things wrong, kept because they cost us something:

**Every number resolves to three artefacts** — a dataset file, a run log, and a results file. We
found projected figures presented as measured in our own draft papers, and simulation output
treated as live results in another. "Preserved from a prior draft" is not provenance.

**Absence of a failure signal is not evidence of correctness.** We shipped a retrieval path that
silently degraded when a vector index was missing, and it went undetected for months because
nothing failed loudly. The same pattern later turned up in our own CI, where suppressed test files
kept the build green while real defects hid behind the suppression. Both are now fixed, and the
principle generalises: a check that cannot fail is not a check.

**Research may reject the thesis.** Every programme above has a stop condition written before the
data arrives.

**Claims map to mechanisms.** Anything reaching the README links to a shipped capability or a
benchmark artefact. That is why this page has so many *Research* labels.

---

## Reproducing our work

Benchmark methods and results are published as they clear the artefacts gate. Where a programme
above says *not started*, there is nothing to reproduce yet, and we would rather say that than
publish a figure we cannot trace.

---

*Status labels current as of the release this file ships with. Programme status changes are
recorded in `CHANGELOG.md`, not silently edited here.*
