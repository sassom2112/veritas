# VERITAS — Agent Harness Reference

## System Intent

Autonomous Windows forensic investigation with adversarial verification. The pipeline closes
the AI forensic trust gap not by improving investigator accuracy but by making hallucinated
findings structurally unable to reach the final report.

Epistemic argument: "A verification result is only as independent as the information boundary
between the investigator and the verifier." This is the through-line for all architecture
decisions in this repo.

---

## The Information Boundary

`_build_verifier_message()` in `verifier.py` is the sole handoff construction point between
investigator and verifier. This is the information boundary enforcement mechanism.

**What crosses the boundary:**
- `technique_id` — MITRE ATT&CK identifier
- `tool_output` — raw tool return value (first 1500 chars)
- `artifact_hint` — filesystem path or memory address hint

**What does not cross:**
- Investigator reasoning chain
- Phase 1 scores or technique labels
- Agent confidence levels or prior session context

This is structural isolation enforced by a session boundary in code — not a prompt instruction.
If additional verifier context is ever needed, change `_build_verifier_message()` explicitly.
Do not add investigator context to `_VERIFIER_SYSTEM`.

---

## Agent Roster

### Disk Agent — `blue_agent.py`
- **System prompt:** `_DISK_AGENT_SYSTEM`
- **VERITAS_LAYER:** `disk`
- **Tool grants:** `_DISK_BINARIES` allowlist — Sleuth Kit, registry tools, grep, find
- **Receives:** disk mount path; optional prior campaign IOCs
- **Does not receive:** Phase 1 scores, technique labels, Memory Agent output
- **Budget:** 5 rounds × 3 calls (Pass 2 agentic loop)
- **Valid trajectory:** deterministic sweep → agentic investigation → `record_finding` per technique; no Volatility or memory tool invocations

### Memory Agent — `memory_agent.py`
- **System prompt:** `_MEMORY_AGENT_SYSTEM`
- **VERITAS_LAYER:** `memory`
- **Tool grants:** `_MEMORY_BINARIES` allowlist — Volatility 3 plugins only
- **Receives:** raw memory image path
- **Does not receive:** Disk Agent findings, Phase 1 scores
- **Budget:** 5 rounds × 3 calls
- **Valid trajectory:** Volatility plugins → `record_finding` per technique; no disk tool invocations (fls, rip.pl, etc.)

### Forensic Auditor — `auditor_agent.py`
- **System prompt:** `_AUDITOR_SYSTEM`
- **VERITAS_LAYER:** unset (inherits `_ALLOWED_BINARIES` — full SIFT allowlist)
- **Receives:** findings list (technique IDs and names only)
- **Does not receive:** investigator reasoning, Phase 1 scores, agent confidence
- **Budget:** 5 rounds × 2 tool calls per technique; concurrent via `asyncio.gather`
- **Valid trajectory:** ≥1 real forensic tool call per technique → one `record_verdict` call with `verdict` ∈ {CONFIRMED, REFUTED, INCONCLUSIVE}

### Verifier — `verifier.py`
- **System prompt:** `_VERIFIER_SYSTEM`
- **VERITAS_LAYER:** `claim['source_layer']` — set per-claim at invocation
- **Input construction point:** `_build_verifier_message()` only — this is the information boundary enforcement
- **Receives:** `technique_id`, `tool_output[:1500]`, `artifact_hint`
- **Does not receive:** investigator reasoning chain (excluded at construction, not by prompt)
- **Budget:** `MAX_VERIFY_CALLS = 4` per claim; concurrent via `asyncio.gather`
- **Valid trajectory:** N tool calls (N ≤ 4) → exactly one `record_verdict` call; if N = 4 without verdict, return INCONCLUSIVE

---

## Data Contracts

All cross-agent data uses TypedDicts from `contracts.py`. Do not pass raw dicts or strings
across agent boundaries.

| Type | Crosses | Key fields |
|---|---|---|
| `LayerClaim` | Phase 1 → Phase 2 gate | `technique_id`, `source_layer`, `tool_output`, `artifact_hint` |
| `SameLayerVerdict` | Phase 2 → Phase 3 gate | `technique_id`, `source_layer`, `verdict` |
| `CrossVerdict` | Phase 3 → adjudicate | `technique_id`, `corroboration` |
| `FinalTechniqueResult` | adjudicate → report | `technique_id`, `same_verdict`, `cross_verdict`, `final` |

Phase 3 (`cross_verifier.py`) runs only on Phase 2 CONFIRMED claims. Enforced in
`investigate.py:run_cross_layer()`, not in the cross-verifier itself.

---

## Deterministic Budget Caps

| Phase | Constant | File | Value |
|---|---|---|---|
| Phase 1 — disk investigation | `MAX_ROUNDS = 5`, `TOOLS_PER_ROUND = 3` | `blue_agent.py` | 15 calls/agent |
| Phase 1 — memory investigation | `MAX_ROUNDS = 5`, `TOOLS_PER_ROUND = 3` | `memory_agent.py` | 15 calls/agent |
| Phase 2 — same-layer verify | `MAX_VERIFY_CALLS` | `verifier.py` | 4 calls/claim |
| Phase 3 — cross-layer corroborate | `MAX_VERIFY_CALLS` | `cross_verifier.py` | 4 calls/claim |
| Cost ceiling | `TARGET_MAX_COST_USD` | `investigate.py` | $20/host |

---

## Verdict Invariants

| Verdict | Condition |
|---|---|
| `CONFIRMED` | Positive tool return value — artifact physically present |
| `REFUTED` | Evidence of absence — artifact not where the technique requires it |
| `INCONCLUSIVE` | Budget exhausted, timeout, or insufficient tool output |
| `HIGH_CONFIRMED` | Phase 2 CONFIRMED + Phase 3 CORROBORATED (cross-layer bonus) |
| `DISPUTED` | Phase 2 CONFIRMED + Phase 3 CONTRADICTED (flag for review) |

**`INCONCLUSIVE ≠ REFUTED`.** Timeout, budget exhaustion, and insufficient tool output
all return INCONCLUSIVE. Only contradicting evidence returns REFUTED. This is the
"fails safe" property. The rocba T1055 Round 1 timeout → INCONCLUSIVE result is the
canonical example. Do not weaken this for convenience.

Phase 3 CONTRADICTED cannot rescue a Phase 2 REFUTED. `_final()` in `cross_verifier.py`
enforces this: `same_verdict` drives, `cross_verdict` annotates.

---

## Structural Guardrails — Enforcement Locations

AGENTS.md does not duplicate enforcement rules. Each constraint is enforced deterministically
at the location named below. To change a constraint, change its enforcement location.
Do not add redundant prompt instructions — they create a false trust anchor and silently
diverge from code.

| Constraint | Enforced at | Mechanism |
|---|---|---|
| Hard-blocked injection tokens (22) | `sift_server.py` gate 1 | String match before any subprocess call |
| Binary allowlist (53 binaries, layer-aware) | `sift_server.py` gate 2 | `VERITAS_LAYER` env var selects allowlist on import |
| Quote-aware pipeline parsing | `sift_server.py` gate 3 | Stateful single-quote tracking; `\|` inside quotes is not a separator |
| Write-target guard | `sift_server.py` gate 4 | `os.path.realpath()` must resolve inside `reports/` |
| Information boundary | `verifier.py:_build_verifier_message()` | Only `technique_id`, `tool_output`, `artifact_hint` constructed into message |
| Contract schema | `contracts.py` TypedDicts | Typed boundaries at every agent handoff point |
| Audit log atomicity | `sift_server.py` | `os.open + os.write` before every subprocess call; append-only |

---

## Model Routing (Sprint 4 Target)

Current: all agents use `claude-sonnet-4-6`. Target after Sprint 4:

| Task | Current | Target | Reason |
|---|---|---|---|
| Disk/Memory investigation | `sonnet-4-6` | `sonnet-4-6` | Complex multi-step reasoning; keep |
| Auditor challenge | `sonnet-4-6` | `sonnet-4-6` | High-stakes adversarial; keep |
| Verdict synthesis (`record_verdict`) | `sonnet-4-6` | `haiku-4-5-20251001` | Tool call only; no reasoning required |
| Claim synthesis (`record_finding`) | `sonnet-4-6` | `haiku-4-5-20251001` | Tool call only; no reasoning required |

Env vars (Sprint 4): `VERITAS_MODEL` for investigation turns; `VERITAS_SYNTHESIS_MODEL`
for synthesis turns. Routing change is safe if Sprint 2 output eval passes after the switch.

---

## Hard Rules

- **Do not start `sift_server.py` manually.** It spawns as an MCP subprocess via
  `StdioServerParameters`. A manual terminal instance creates a second server that breaks
  tool routing.
- **Do not use the old role names** (deprecated before commit `2eeb98b`). Current
  names: Disk Agent, Memory Agent, Forensic Auditor, Verifier.
- **Do not run the deprecated triage script.** Entry point is
  `investigate.py --case <path>`.
- **Do not add enforcement rules to this file.** Point to the enforcement location in the
  table above. Duplicate rules here will silently diverge from code and mislead future agents.
- **Do not merge `future/cross-layer-verification` to `main`** until Sprint 2 eval harness
  passes against nfury ground truth: 15 confirmed, 4 refuted expected.

---

## Branch Discipline

| Branch | Purpose | State |
|---|---|---|
| `main` | Hackathon submission — three-phase pipeline (disk + memory → Auditor) | Committed |
| `future/cross-layer-verification` | Four-phase pipeline (+ same-layer Verifier as primary gate) | Active; uncommitted files |

**Uncommitted on `future/cross-layer-verification`:**
`custom-agent/verifier.py`, `custom-agent/contracts.py`, `custom-agent/cross_verifier.py`,
`custom-agent/investigate.py`. Commit before Sprint 2.
