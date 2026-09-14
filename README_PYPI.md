# GraQle — give your AI a memory of how your system actually works

**Turn codebases, documents, policies and decisions into a persistent knowledge graph, so your AI agents reason over architecture and prior lessons instead of re-reading files every session.**

```bash
pip install graqle
```

Models change. Tools change. Your architecture and institutional knowledge should not.

---

## 60-second proof

```bash
# 1. Scan a codebase into a typed knowledge graph
graq scan repo .

# 2. Ask an architectural question, not a file question
graq run "what breaks if I change the payment module?"
# → answer + confidence + evidence trail + active nodes

# 3. Teach it what code cannot tell it
graq learn knowledge "payment module must never call user service directly"
# → persists in the graph. Future reasoning activates this rule.
```

Step 3 is the one that compounds — and the one prompt engineering cannot replace, because it needs a persistent typed graph as the substrate.

---

## Why this matters now

Agents are getting far more capable, and still reconstruct your system from scratch every session. Models are becoming cheaper and interchangeable, which makes the intelligence layer above them — not the model itself — the thing worth owning.

GraQle sits above the model:

- **Architecture, not files.** AI assistants see files. GraQle sees relationships, dependencies and blast radius.
- **Memory that compounds.** Lessons and decisions become durable graph nodes, not chat history.
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

Documents become Document and Section nodes, auto-linked to the code they describe. Markdown, text, RST and AsciiDoc work with the base install; the richer formats need the `[docs]` extra and are reported — never silently skipped — when it's missing.

---

## Works with your stack

**13 LLM backends + any custom HTTP endpoint** — Anthropic, OpenAI, AWS Bedrock, Ollama, Gemini, Groq, DeepSeek, Together, Mistral, OpenRouter, Fireworks, Cohere, llama.cpp.

```yaml
# graqle.yaml
model:
  backend: ollama          # or: anthropic, openai, bedrock, gemini, groq...
  model: llama3
```

Runs fully offline with Ollama or llama.cpp. **Local-first: no telemetry, and your source never leaves your machine.**

**Works with every AI IDE** — Claude Code, Cursor, VS Code + Copilot, Windsurf, via **85 MCP tools** your agent uses automatically.

```bash
graq init    # detects your IDE and wires the tools
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
