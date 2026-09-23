# GraQle — give your AI a memory of how your organisation actually works

**Turn policies, decisions, documents and codebases into a persistent knowledge graph, so your AI agents reason over what your organisation already knows instead of rebuilding a partial picture every session.**

```bash
pip install graqle
```

Models change. Tools change. Your institutional knowledge should not.

**Works with your stack today** — 13 LLM backends plus any custom HTTP endpoint (Anthropic, OpenAI, Bedrock, Ollama, Gemini, Groq, DeepSeek, Together, Mistral, OpenRouter, Fireworks, Cohere, llama.cpp), fully offline with Ollama or llama.cpp, and inside Claude Code, Cursor, VS Code + Copilot or Windsurf via **85 MCP tools**. Local-first: no telemetry, and your source never leaves your machine.

---

## 60-second proof — no code required

Works on a folder with no code in it at all.

```bash
# 1. Turn organisational documents into a typed graph
graq scan docs ./policies
# → 3 files → 12 nodes: 3 Document + 9 Section, linked by SECTION_OF

# 2. Teach it a rule that lives in nobody's file
graq learn knowledge "vendor DPA must be signed before any data access" --domain policy
# → auto-links the rule to the vendor-onboarding doc AND its "Due diligence" section

# 3. Ask across the whole body of knowledge
graq run "what approval is needed for a large refund?"
# → answer + confidence + evidence trail + the sections consulted

# 4. Audit what the organisation has taught it
graq learned
```

Step 2 is the one that compounds — and the one prompt engineering cannot replace, because it needs a persistent typed graph as the substrate. GraQle worked out where that rule belonged on its own.

### The same graph, for code

```bash
graq scan repo .                                    # functions, classes, imports, calls
graq run "what breaks if I change the payment module?"
graq impact payments.py                             # blast radius
```

Software architecture is the deepest-mapped domain today — a wedge, not the boundary.

---

## Why this matters now

Agents are getting far more capable and still start from zero every session. Models are becoming cheaper and interchangeable, which makes the intelligence layer above them — not the model itself — the thing worth owning.

GraQle sits above the model:

- **Relationships, not files.** Assistants see documents and files. GraQle sees how a policy, a decision and the code implementing it relate.
- **Memory that compounds.** Policies, decisions and lessons become durable graph nodes, not chat history.
- **Model independence.** Switch providers or IDEs without rebuilding the intelligence layer.

---

## What you get

| Capability | Command |
|:---|:---|
| Blast radius before a change | `graq impact payments.py` |
| Cross-file security audit | `graq run "find every auth bypass risk"` |
| Architecture Q&A for onboarding | `graq run "how does checkout work end to end?"` |
| Persistent lessons | `graq learn knowledge "..."` |
| Audit what the graph has been taught | `graq learned` |
| Documents, policies, ADRs into the graph | `graq scan docs ./docs` |
| Pre-change safety check | `graq preflight "refactor the auth layer"` |
| CI/CD governance gate | `graq predict "..." --fail-below-threshold` |

---

## Beyond code

```bash
pip install "graqle[docs]"          # PDF / DOCX / PPTX / XLSX parsers

graq scan docs ./docs               # architecture docs, runbooks, specs
graq learn doc ./policies/          # policies, ADRs, decision records
```

Documents become Document and Section nodes, linked by `SECTION_OF` — and to any code that implements them. Markdown, text, RST and AsciiDoc work with the base install; the richer formats need the `[docs]` extra and are reported — never silently skipped — when it's missing.

---

## Configuring your stack

Switching backend is one line — the graph is the constant, the model is a swappable input:

```yaml
# graqle.yaml
model:
  backend: ollama          # or: anthropic, openai, bedrock, gemini, groq...
  model: llama3
```

```bash
graq init    # detects your IDE and wires the MCP tools
```

---

## Trusted answers

Every result carries `confidence`, `graph_health`, `active_nodes` and evidence pointers. Below the confidence floor, GraQle refuses rather than guesses. With no LLM configured it labels output as a placeholder and attaches no confidence score.

---

## Governed autonomy

When agents move from reading to writing, `graq gate-install` routes write/edit/bash operations through governance gates: plans required for risky changes, secret scanning on commits, full audit trail. For deployed systems, `GovernedRuntime.attest()` records what your AI decided, anchored to the public Sigstore Rekor transparency log — verifiable by any third party.

Optional compliance surfaces for regulated deployments cover the EU AI Act, SOX/COSO, ISO/IEC 42001 and GDPR claim limits; compliance frameworks are authorable as data.

→ [Full documentation on GitHub](https://github.com/quantamixsol/graqle)

---

## Pricing

| | Free | Pro ($19/mo) | Team ($29/dev/mo) |
|:--|:--:|:--:|:--:|
| CLI + SDK + 85 MCP tools | Unlimited | Unlimited | Unlimited |
| 13 LLM backends + custom | ✅ | ✅ | ✅ |
| Graph nodes | 1,000 | 25,000 | Unlimited |
| Cloud sync | 1 project | 3 projects | Unlimited |
| Shared team graphs + lessons | — | — | ✅ |

[**graqle.com →**](https://graqle.com)

---

*Built by Quantamix Solutions B.V. · Patent pending EP26167849.4 · Local by default · Your code never leaves your machine*

<!-- mcp-name: io.github.quantamixsol/graqle -->
