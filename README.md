<div align="center">

<img alt="GraQle — persistent organisational intelligence for AI agents." src="https://raw.githubusercontent.com/quantamixsol/graqle/master/assets/hero-dark-hq.png" width="800">

# GraQle — give your AI a memory of how your organisation actually works

> Turn the context your organisation already has — **codebases, documents, policies, decisions and workflows** — into a persistent typed knowledge graph, so Claude Code, Cursor, Copilot and other agents reason over architecture, dependencies, prior lessons and evidence instead of re-reading disconnected files every session.

**Models change. Tools change. Your architecture and institutional knowledge should not.**

[![PyPI](https://img.shields.io/pypi/v/graqle?color=%2306b6d4&label=PyPI)](https://pypi.org/project/graqle/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-06b6d4.svg)](https://python.org)
[![LLM Backends](https://img.shields.io/badge/backends-13%20%2B%20custom-06b6d4.svg)]()
[![Model Agnostic](https://img.shields.io/badge/model-agnostic-06b6d4.svg)]()
[![MCP Tools](https://img.shields.io/badge/MCP%20tools-85-06b6d4.svg)]()
[![Local-first](https://img.shields.io/badge/local--first-no%20telemetry-22c55e.svg)](#enterprise-trust)
[![Patent-pending](https://img.shields.io/badge/patent-pending%20EP26167849.4-7c3aed.svg)](#patent--license)

```bash
pip install graqle
```

[Website](https://graqle.com) · [Quickstart](#90-second-proof) · [How it works](#how-it-works) · [Governed autonomy](#governed-autonomy) · [Regulated deployments](#regulated-deployments) · [Changelog](./CHANGELOG.md) · [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=graqle.graqle-vscode)

<!-- mcp-name: io.github.quantamixsol/graqle -->

</div>

---

## Why GraQle exists

Your organisation already knows the answer. It just can't hand it to an AI.

The refund threshold lives in a policy document. The reason you retain records for seven years is in an ADR nobody re-reads. The incident that moved validation into the service layer is in someone's head. The dependency that makes payments fragile is in the code. Every one of those is real knowledge — and none of it is connected to any of the others, so no model can reason across it.

Each AI session starts from zero and rebuilds a partial picture from whatever files fit in the context window. Then the window closes and the picture is gone.

GraQle builds that connection once, keeps it, and grows it.

- **Relationships, not files.** Assistants see documents and files. GraQle sees how a policy, a decision and the code that implements it relate — and what breaks when one of them changes.
- **Memory that compounds.** Policies, decisions, lessons and architecture become durable graph nodes instead of disappearing with a chat session. Teach it once; every future session starts from there.
- **Model independence.** Swap models, providers or IDEs without rebuilding the intelligence layer.

---

## 90-second proof — no code required

Point GraQle at policies, ADRs, runbooks or specs. **Nothing else needed — this works on a folder with no code in it at all.**

```bash
pip install graqle

# 1. Turn a folder of organisational documents into a typed graph
graq scan docs ./policies
# → 3 files → 12 nodes: 3 Document + 9 Section, linked by SECTION_OF

# 2. Teach it a rule that lives in nobody's file
graq learn knowledge "vendor DPA must be signed before any data access" --domain policy
# → extracts the entity "DPA", then SEMANTICALLY_RELATED-links the rule to
#   the vendor-onboarding document AND to its "Due diligence" section

# 3. Ask across the whole body of knowledge
graq run "what approval is needed for a large refund?"
# → answer + confidence + evidence trail + the exact sections consulted

# 4. Audit what the organisation has taught it
graq learned
```

Step 2 is the one that compounds, and the one no amount of prompt engineering replaces: it needs a persistent typed graph as the substrate. GraQle found where that rule belonged on its own — you never told it which document to attach it to.

Markdown, text, reStructuredText and AsciiDoc parse with the base install. PDF, DOCX, PPTX and XLSX need `pip install "graqle[docs]"` — without it those files are skipped and reported, never silently dropped.

### The same graph, for code

Where a codebase is part of the picture, it enters the same graph and connects to the documents that govern it:

```bash
graq scan repo .
# → functions, classes, modules, imports, calls — architecture mapped in seconds

graq run "what breaks if I change the payment module?"
# → traces cross-file call + import chains, activates the relevant subgraph

graq impact payments.py        # blast radius before you touch anything
```

Software architecture is the deepest-mapped domain today — typed down to the function — and for engineering teams it is usually the fastest way to see the value. It is a wedge, not the boundary.

---

## The compounding advantage

The first time you run GraQle, it knows what you gave it. After a month, it knows your patterns. After a year, it holds the policies, decisions, architectural lessons and document context your organisation accumulated — and activates the relevant ones on the work that is about to repeat an old mistake.

This is the part that survives model churn. When you switch provider or IDE, the graph is unchanged. You are not re-teaching a new model what your organisation knows; you are pointing a different model at intelligence you already own.

> **Own the intelligence your models and agents create.** Enterprises can own their data and still lose the reasoning state accumulated inside external AI tools — the decisions, the corrections, the hard-won context. The graph is a local file you control.

---

## How it works

1. **Scan** → Documents, policies, ADRs and specs become Document and Section nodes. Codebases enter the same graph through AST + dependency analysis (functions, classes, modules, imports, calls). One substrate, whatever the source.
2. **Connect** → Relationships become first-class: `SECTION_OF`, `SEMANTICALLY_RELATED`, `IMPORTS`, `CALLS`, `DEFINES`. Taught knowledge is auto-linked to the documents and code it concerns. This is what makes reasoning *across* sources possible.
3. **Activate** → A pre-reasoning layer scores each node for relevance, confidence and risk **before** the LLM runs, so the model receives the relevant subgraph instead of the whole repository.
4. **Reason** → Multiple agents debate. Outputs carry `confidence`, `graph_health`, `active_nodes` and evidence pointers.
5. **Validate** → Answers below the confidence floor are refused rather than guessed.
6. **Learn** → Lessons, decisions and documents become durable graph knowledge that activates on future work.
7. **Govern & commit** → When agents move from reading to writing, gates intercept write-class operations, and decisions can be cryptographically committed.

The pipeline runs through five named phases — **ANCHOR → ACTIVATE → GENERATE → VALIDATE → COMMIT**. Each phase is governance-gated, evidence-attached and audit-logged.

API defaults: `confidence_threshold=0.65` (refusal floor), `gate_threshold=0.60` (gate-status floor). Both configurable per call.

---

## Works with the AI tools you already use

You don't need another UI. GraQle runs inside the tools your team already has.

```jsonc
// .mcp/config.json
{ "graqle": { "command": "graq", "args": ["mcp", "serve"] } }
```

**85 MCP tools** — every operation Claude Code, Cursor, VS Code Copilot or Windsurf needs, exposed as a governed tool with confidence scores, evidence pointers and audit-trail entries. No prompt engineering, no glue code. (Each tool is also aliased `kogni_*` for backward compatibility.)

```bash
graq init              # detects your IDE, wires the tools, writes the project constitution
```

`graq init` renders one rulebook for every client — Claude Code → `CLAUDE.md`, OpenAI Codex → `AGENTS.md`, Cursor → `.cursorrules`, Windsurf → `.windsurfrules` — so editing it once keeps them all in sync.

---

## Model independence

Anthropic · OpenAI · AWS Bedrock · Ollama · Gemini · Groq · DeepSeek · Together · Mistral · OpenRouter · Fireworks · Cohere · llama.cpp — plus any custom HTTP endpoint.

```yaml
# graqle.yaml — smart task routing
backends:
  reasoning:  anthropic/claude-sonnet-4-6   # quality work
  embedding:  bedrock/titan-v2              # cheap + fast
  summaries:  ollama/llama3                 # local + free
```

Runs **fully offline** with Ollama or llama.cpp. Route different task types to different providers, or race two providers and take the first useful answer. The graph is the constant; the model is a swappable input.

---

## What teams use it for

| Use case | Command |
|:---|:---|
| **Policies, ADRs and specs into the graph** | `graq scan docs ./policies` · `graq learn doc ./decisions/` |
| **Institutional memory that outlives the session** | `graq learn knowledge "..."` · `graq learned` |
| **Ask across documents, decisions and code at once** | `graq run "what approval is needed above the refund limit?"` |
| Onboarding without a walkthrough | `graq run "how does checkout work end to end?"` |
| Blast radius before a change | `graq impact payments.py` |
| Cross-file security audit | `graq run "find every auth bypass risk"` |
| Pre-change safety check | `graq preflight "refactor the auth layer"` |
| CI/CD governance gate | `graq predict "..." --fail-below-threshold` |

---

## Trusted answers

Every reasoning result carries the signals that make it inspectable rather than magical:

- **`confidence`** — an opaque score between 0.0 and 1.0; below the floor, GraQle refuses instead of guessing.
- **`graph_health`** — whether the graph had enough connected context to answer well.
- **`active_nodes`** — exactly which parts of your system informed the answer.
- **Evidence pointers** — the path back to the source the claim rests on.

These are not only governance features. They are what lets a human decide whether to act on an answer.

> If no LLM backend is configured, GraQle labels its output as a placeholder and does not attach a confidence score — an unconfigured install never looks like a real answer.

---

## Governed autonomy

Reading is low-stakes. Writing and acting are not. As soon as an agent can edit files, run commands or take production actions, you need something stronger than a good prompt.

```bash
graq gate-install      # one-time, project-local
```

This routes native write/edit/bash operations through GraQle's governance gates and adds a `permissions` backstop to `.claude/settings.json`. Plans required for risky changes. Trade-secret scanning on commits. Path-traversal hardening on subprocess capture. CG-01 through CG-20 — all on, all auditable.

**Governance here is what lets you give agents more autonomy, not less.** The gate is the reason a write-capable agent is a reasonable thing to run.

→ [Governance Gate spec](./docs/governance-gate.md)

### When your AI makes production decisions

For deployed systems, the same substrate records what your AI decided:

```python
from graqle.governance.runtime import GovernedRuntime

gov = GovernedRuntime(salt="your-deploy-salt")

def score_application(app):
    decision = model.predict(app)                # your deployed AI, untouched
    gov.attest(                                  # <-- the one added line
        domain="loan", model_id="credit-risk-v4",
        inputs={"applicant_ref": gov.pseudonymize_ref(app.id)},   # PII-safe
        output={"decision": decision.label, "reason_code": decision.reason},
    )
    return decision
```

Capture is out-of-band — **0 ms added to your write path**. Records are canonicalised (RFC 8785), Merkle-rooted (RFC 6962), ed25519-signed and anchored to the public Sigstore Rekor transparency log, so any third party can verify a record without access to your infrastructure, or ours.

```bash
graqle govern serve --config graqle.yaml   # continuous anchoring worker
graqle govern health                       # JSON snapshot for any monitor
```

→ [`examples/runtime_attest_production_decisions.py`](./examples/runtime_attest_production_decisions.py)

---

## One substrate, two operating modes

|  | **Build-time** (dev intelligence) | **Run-time** (decision attestation) |
|---|---|---|
| Governs | how your AI **writes code** | what your deployed AI **decides** |
| Trigger | a code change | a production decision |
| Emits | reviewed, impact-analysed, audit-logged changes | a tamper-evident, third-party-verifiable record |
| Status | **GA** | **GA** |

Same graph, same evidence model, same audit substrate. Most teams start with build-time and never need the second mode — that's fine, and it's why it lives here rather than in the hero.

---

## Enterprise trust

| | |
|---|---|
| **Local-first** | The graph is a file in your project. Default operation is entirely on your machine. |
| **No telemetry** | GraQle does not phone home, collect usage data, or send analytics. |
| **No code upload** | Source never leaves your machine unless you explicitly log in and opt in to cloud sync — which syncs graph artefacts, never your source. |
| **Secret scanning** | 200+ regex patterns + entropy detection + AST scan on every output candidate. |
| **PyPI Trusted Publishing** | OIDC-only — no long-lived API tokens in our pipeline. |
| **Sigstore signatures** | Every wheel signed by our GitHub Actions identity. Verify with `graq trustctl verify --version <v>`. |
| **CycloneDX SBOM** | Attached to every GitHub Release. |
| **Reproducible builds** | `SOURCE_DATE_EPOCH`-pinned; rebuild from tagged source and compare checksums. |
| **Survive-disappearance** | Production audit records anchor to public Sigstore Rekor — verifiable even if Quantamix disappears. |

→ [SECURITY.md](./SECURITY.md) · Report vulnerabilities to **security@quantamixsolutions.com**

---

## Regulated deployments

If you operate in a regulated environment, the same substrate produces compliance evidence. If you don't, you can skip this section entirely — nothing above depends on it.

[![EU AI Act–aligned](https://img.shields.io/badge/EU%20AI%20Act-aligned-22c55e.svg)](./docs/compliance/eu-ai-act/)

**GraQle is EU AI Act–aligned by design.** We give your high-risk AI system the signals, audit trail, and disclosure primitives you need to satisfy your own Article 9 risk-management file — without GraQle itself being subject to the high-risk obligations. Articles 6, 9, 12, 13, 14, 15, 25, 50 became applicable on 2026-08-02.

```bash
graq compliance switch on        # flips every EU-AI-Act-aware subsystem
graq compliance status           # what's actually armed
graq compliance export --since 2026-08-01 --sha256-sidecar   # Article 12 evidence
```

**Three non-claims, kept legally clean:**

- GraQle is **NOT** itself a high-risk AI system (no Annex III category applies).
- GraQle is **NOT** a GPAI provider under Article 51 (we use third-party LLMs; we don't place one on the EU market).
- We provide signals, audit primitives and conformity-assessment evidence inputs. We never say *compliant* or *certified* — a CI invariant blocks any release that introduces such a field.

**Beyond the EU.** The evidence substrate is framework-neutral, and compliance packs are **data, not code** — a framework is two files (`pack.yaml` + `schema.json`), no Python and no engine change:

- **SOX / COSO** — ships today as the `x-sox` pack: internal control IDs, financial-statement assertions, reporting periods, management review.
- **ISO/IEC 42001** — Cl. 6.2 and Cl. 9.1 mapped through the baseline-document and periodic-assessment artefacts.
- **GDPR** — `gdpr_processor_only` is a canonical claim limit on every record.
- **NIST AI RMF, SOC 2, HIPAA and sector frameworks** — authorable as packs today; first-party packs and cross-framework mappings are open for contribution.

The claim-limits taxonomy makes the *scope* of every decision explicit, so a downstream auditor can answer "what does this record **not** claim?" without guesswork.

→ [Full Article-by-Article mapping](./docs/compliance/eu-ai-act/) · [How to contribute a mapping](./CONTRIBUTING-COMPLIANCE.md)

---

## Pricing

| Tier | What you get |
|---|---|
| **Free** | Local graphs · core SDK · 85 MCP tools · governance gates · `attest()` runtime · self-hosted anchoring to public Rekor |
| **Pro — $19/mo** | Cloud sync · priority models · hosted Rekor relay |
| **Team — $29/dev/mo** | Shared graphs · team-wide lessons · audit-log retention · SOC 2 evidence pack |
| **Enterprise** | On-prem · custom backends · dedicated support · regulated-deployment SLAs · [contact us](mailto:sales@quantamixsolutions.com) |

The free tier is real: the verifier, the runtime attestation path and the continuous anchoring worker are all in the open-source SDK.

---

## Token economics

Activating a relevant subgraph costs fewer tokens than repeatedly feeding a model whole files. On a 50,000-node enterprise codebase, a sourced case study puts a 4-developer team at **−53%** against a flat-file baseline in year one, and **−88%** once local models carry the routine work.

Treat this as supporting evidence rather than the reason to adopt: inference prices keep falling, while context fragmentation and lost institutional knowledge do not.

→ [Read the full case study](./docs/case-study-token-economics.md) — math, sources, and a snippet to re-run it on your own numbers.

---

## Recent releases

- **v0.83.0** — Scheduler contract for `graq rebuild` (`--headless` / `--json`, exit codes) + reasoning-quota metering.
- **v0.75.0** — Optional EU AI Act layer, off by default, behind a tamper-evident irreversible latch.
- **v0.73.0** — Cost is observability, never a quality gate: reasoning never truncates to save money.
- **v0.72.0** — One constitution, every AI client (Claude Code, Codex, Cursor, Windsurf).
- **v0.62.0** — `graqle govern serve` continuous anchoring worker + health snapshot.

→ [Full changelog](./CHANGELOG.md)

---

## Patent & license

Core methods are patent-pending: **EP26167849.4** (filed 2026-03-25), **EP26162901.8** (CIP), and **EP26166054.2** (CogniGraph divisional). The SDK source is fully auditable under the GraQle License — see [LICENSE](./LICENSE). Reimplementation of the patented methods outside this SDK requires a separate patent license.

→ [github.com/quantamixsol/graqle](https://github.com/quantamixsol/graqle) — issues, discussions and contributions welcome.

---

<div align="center">

**GraQle is built by [Quantamix Solutions](https://quantamixsolutions.com).**
*The intelligence that survives when the model, the agent and the interface change.*

</div>
