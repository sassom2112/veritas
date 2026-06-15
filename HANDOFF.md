# Handoff — future/cross-layer-verification (2026-06-14)

## Current state

The cross-layer verification sprint is complete. The pipeline now has three phases:

| Phase | File | Status |
|---|---|---|
| Phase 1: Investigation | `disk_agent.py` + `memory_agent.investigate_layered()` | Done, committed |
| Phase 2: Same-layer blind replication (PRIMARY GATE) | `verifier.py` | Done, **uncommitted** |
| Phase 3: Cross-layer corroboration (bonus) | `cross_verifier.py` | Done, **uncommitted** |
| Orchestration | `investigate.py run_cross_layer()` | Done, **uncommitted** |
| Contracts | `contracts.py` | Updated, **uncommitted** |

**Uncommitted files (commit before next sprint):**
- `custom-agent/verifier.py` — new, real MCP session implementation
- `custom-agent/contracts.py` — added `SameLayerVerdict`, updated `FinalTechniqueResult`
- `custom-agent/cross_verifier.py` — `adjudicate()` now takes `same_layer_verdicts` as primary
- `custom-agent/investigate.py` — Phase 2 wired before Phase 3; updated phase labels

**Hackathon deadline: June 15, 2026.** Demo video + Devpost submission still required.
SIFT workstation: `192.168.1.71` (ping before assuming online).
nfury ground truth: `reports/nfury-auditor-transcript.json` — 15 confirmed, 4 refuted.

---

## What was built this session

**`verifier.py`** — Phase 2 same-layer blind replication.
- Real MCP session per claim, `VERITAS_LAYER=claim['source_layer']`
- `_build_verifier_message()` is the enforcement point: only `technique_id`, `tool_output`,
  `artifact_hint` cross to the verifier. Reasoning never crosses.
- `_RECORD_VERDICT_TOOL` + `tool_choice={'type': 'any'}` — forced structured verdict, no text parsing
- `MAX_VERIFY_CALLS = 4` per claim
- All claims verified concurrently via `asyncio.gather`

**`contracts.py`** — Added `SameLayerVerdict` TypedDict. Updated `FinalTechniqueResult`:
- `same_verdict` field added (drives `final`)
- `final` values: `HIGH_CONFIRMED | CONFIRMED | DISPUTED | REFUTED | INCONCLUSIVE`
- `cross_verdict` is now annotation-only — cannot rescue a Phase 2 REFUTED

**`cross_verifier.adjudicate()`** — new signature:
```python
adjudicate(same_layer_verdicts, disk_claims, memory_claims, disk_verdicts, memory_verdicts)
```
`_final()` function: same_verdict drives, cross_verdict annotates. Phase 3 CORROBORATED
upgrades CONFIRMED → HIGH_CONFIRMED.

**`investigate.py run_cross_layer()`** — Phase 2 now runs between Phase 1 and Phase 3.
Only Phase 2 CONFIRMED claims go to Phase 3.

**All docs updated** — `README.md`, `architecture.md`, `SUBMISSION.md`, `index.md`, `the-game.md`:
- "Cynic/Optimist" removed; replaced with "Disk Agent", "Memory Agent", "Auditor"
- `fast-triage/fast_triage.py` references removed
- Terminal 1/2 startup pattern corrected (sift_server spawns automatically)
- "Three hosts" → "Four hosts" throughout

**Epistemic through-line** saved to `/home/username/research/epistemic-through-line.md` —
the formal argument that VERITAS blinded replication and CATT-CCS constraint inflation
are the same epistemic argument in two domains. Memory index updated.

---

## Sprint backlog (ordered by value)

Mapped against the Google "New SDLC with Vibe Coding" whitepaper (May 2026). Each sprint
addresses a specific gap between VERITAS's current harness and agentic engineering best practice.

---

### Sprint 1 — Harness documentation (AGENTS.md)

**Whitepaper gap:** "Set up an AGENTS.md. Start with ten lines: stack, conventions, hard
rules, workflow. Add a rule every time the agent does something it should not do again."
VERITAS has the harness implemented in code but it isn't configurable without editing source.
A cold Claude session cloning this repo has no rule file.

**Deliverable:** `AGENTS.md` at repo root. Contents:
- Agent roles: Disk Agent (`blue_agent.py`), Memory Agent (`memory_agent.py`),
  Auditor (`auditor_agent.py`), Verifier (`verifier.py`)
- Tool grants per agent (VERITAS_LAYER values, binary allowlists per layer)
- Budget caps per phase: Phase 1 (15 calls/agent), Phase 2 (4 calls/claim),
  Phase 3 (4 calls/claim), target ≤ $20/host
- What each agent receives / explicitly does not receive (the information boundary)
- Verdict definitions: CONFIRMED requires positive tool return; INCONCLUSIVE ≠ REFUTED
- Hard rules: no sift_server manual startup, no fast_triage path, no Cynic/Optimist names

**Also:** Extract system prompts from Python files into versioned config strings in a
single `prompts.py` or `prompts/` directory. Current state: `_DISK_AGENT_SYSTEM`,
`_VERIFIER_SYSTEM`, `_AUDITOR_SYSTEM` are hardcoded strings buried in agent files.

---

### Sprint 2 — Eval harness (output + trajectory)

**Whitepaper gap:** "Without both [tests and evals], the practice is always vibe coding,
regardless of how sophisticated the prompts are." VERITAS has ground truth (48 claims,
32/16 across 4 hosts) but no automated eval. We cannot verify that a code change didn't
break the results. We do not evaluate whether the agent used the right tools in the right order.

**Two eval types the whitepaper distinguishes:**
- **Output eval:** Does `run_investigation()` produce the correct CONFIRMED/REFUTED set?
- **Trajectory eval:** Does the audit log show the expected tool sequence for known
  techniques? (T1569.002 should always call `find` or `fls` looking for `psexesvc.exe`;
  T1055 should always include `malfind`.)

**Deliverable:** `evals/` directory:
```
evals/
  ground_truth/
    nfury.json         # 19 claims, expected verdicts per technique
    tdungan.json       # 17 claims
    nromanoff.json     # 7 claims
    rocba.json         # 5 claims
  eval_output.py       # runs against synthetic image, compares final verdicts
  eval_trajectory.py   # parses audit_log.jsonl, checks tool sequence per technique
  run_evals.sh         # runs both suites, exits 1 on regression
```

**Gate:** `run_evals.sh` must pass before any Sprint 3+ code merges to main.
This is the regression suite the whitepaper says should exist before AI changes anything.

---

### Sprint 3 — Technique playbooks as dynamic skills

**Whitepaper gap:** "Agent Skills: structured portable packages of procedural knowledge
that the agent loads only when the task calls for it... the agent sees only lightweight
metadata at startup, loads full instructions when a task matches."
Every VERITAS system prompt is fully static. The Auditor reads generic investigation
instructions when it should load a T1055-specific playbook vs. a T1569-specific playbook.
This is the paper's "context rot from overloaded prompts."

**Deliverable:** `skills/` directory with per-technique verification playbooks:
```
skills/
  T1055-process-injection.md    # malfind first, vadwalk PID, dumpfiles physaddr
  T1003.001-lsass-dump.md       # comsvcs, procdump, strings on suspicious binary
  T1569.002-psexec.md           # find psexesvc.exe, fls at Windows/System32
  T1071.001-c2-web.md           # netscan ESTABLISHED, check against CDN list
  ...
```

The Auditor loads the relevant skill for the technique being challenged. Generic system
prompt drops from ~2KB to ~300 tokens per challenge. Technique-specific playbook adds
~200 tokens on demand. Net: same information, lower token cost, higher signal density.

**Wire-in:** `auditor_agent.py` loads skill by technique_id before each challenge round.
Skills can be updated without touching agent code — they're config, not source.

---

### Sprint 4 — Model routing

**Whitepaper gap:** "Uses large, advanced models for complex tasks; routes deterministic/
lower-complexity tasks to smaller, faster, cheaper models."
VERITAS runs `claude-sonnet-4-6` for everything, including verdict synthesis turns where
the model has 4 tool outputs and just needs to call `record_verdict`.

**Routing table:**
| Task | Current | Target | Reason |
|---|---|---|---|
| Investigation reasoning (disk/memory) | sonnet-4-6 | sonnet-4-6 | Complex, keep |
| Auditor challenge reasoning | sonnet-4-6 | sonnet-4-6 | High stakes, keep |
| Verdict synthesis (`record_verdict`) | sonnet-4-6 | haiku-4-5 | Tool call only, no reasoning |
| Claim synthesis (`record_finding`) | sonnet-4-6 | haiku-4-5 | Tool call only, no reasoning |
| Pass 1 scoring | no model | no model | Already correct |

**Target:** Cut per-host cost from ~$14 to ~$8 without changing verdict quality.
Measurable with the Sprint 2 eval harness — if output eval passes after routing change,
the routing is safe.

**Implementation:** `os.environ.get('VERITAS_SYNTHESIS_MODEL', 'claude-haiku-4-5-20251001')`
separate from `VERITAS_MODEL`. Synthesis turns use synthesis model; investigation turns
use investigation model.

---

### Sprint 5 — Observability layer

**Whitepaper gap:** "Observability: Logs, traces, evaluations, cost and latency metering.
Without observability, there is no way to tell whether the agent is doing well or quietly drifting."
VERITAS knows total cost (~$14) from manual inspection. We cannot see where cost goes
within an investigation or whether it's drifting upward across hosts.

**Deliverable:** Structured metrics output appended to each investigation report:
```json
{
  "metrics": {
    "phases": {
      "disk_agent": {"tool_calls": 15, "elapsed_s": 94, "claims": 8},
      "memory_agent": {"tool_calls": 20, "elapsed_s": 88, "claims": 5},
      "verifier": {"tool_calls_total": 52, "claims_verified": 13, "elapsed_s": 45},
      "cross_verifier": {"tool_calls_total": 24, "claims_corroborated": 8, "elapsed_s": 38}
    },
    "total_tool_calls": 111,
    "estimated_cost_usd": 13.80,
    "token_counts": {"input": 284000, "output": 18400}
  }
}
```

**Also:** Add cost ceiling check. If `estimated_cost_usd > TARGET_MAX_COST_USD (20.0)`,
log a warning before Phase 3 starts. Operator can abort Phase 3 to stay under budget.

---

### Sprint 6 — INCONCLUSIVE feedback loop

**Whitepaper gap:** "Evaluate against a benchmark suite, diagnose failures by clustering
root causes, optimize the prompts or tools that caused them, verify fixes against a regression
suite, and monitor production traffic for new failure modes. Each cycle compounds."
INCONCLUSIVE in VERITAS is currently a dead end — it enters the report and nothing happens.
The rocba T1055 Round 2 recovery (after Round 1 timeout) proves recovery works. Make it systematic.

**Two cases to handle:**
1. **Budget exhausted before verdict** — verifier used all 4 calls without concluding.
   Recovery: widen artifact hint, retry once with 2 additional calls targeting the specific
   artifact mentioned in the original `artifact_hint`.
2. **malfind / heavy plugin timeout** — the `120s` subprocess timeout fires mid-execution.
   Recovery: retry with direct PID-targeted invocation (`windows.malfind --pid <pid>`)
   rather than full-image scan.

**Implementation:** `verifier.py` — if `verdict == 'INCONCLUSIVE'` and `calls_used < MAX_VERIFY_CALLS`:
retry with narrowed search. If `calls_used == MAX_VERIFY_CALLS`: INCONCLUSIVE is final,
log `exhausted_budget` reason. If timeout detected in citation: retry with pid-targeted command.

---

## Key invariants to preserve across all sprints

1. **Information boundary is structural, not prompt-based.** `_build_verifier_message()` in
   `verifier.py` is the only place the handoff is constructed. Reasoning never crosses.
   If someone needs to add context to the verifier, they touch this function explicitly.

2. **INCONCLUSIVE ≠ REFUTED.** Timeout, budget exhaustion, and insufficient tool output
   all return INCONCLUSIVE. Only contradicting evidence returns REFUTED. This is the
   "fails safe" property. Do not weaken it for convenience.

3. **Phase 3 never runs on Phase 2 non-CONFIRMEDs.** Cross-layer corroboration only
   runs on what same-layer verification confirmed. A Phase 3 CONTRADICTED cannot rescue
   a Phase 2 REFUTED — this is enforced in `adjudicate()._final()`.

4. **`VERITAS_LAYER` enforcement is at the subprocess level.** The binary allowlist in
   `sift_server.py` reads the env var on import. Structural rejection before `subprocess.run()`.
   This must not be moved to a prompt instruction.

5. **Branch discipline.** `future/cross-layer-verification` only. Do NOT merge to `main`
   until Sprint 2 eval harness exists and passes on nfury ground truth.

---

## Research context

**The epistemic through-line** (canonical: `/home/username/research/epistemic-through-line.md`):
VERITAS blinded replication and CATT-CCS constraint inflation are the same argument.
"A verification result is only as independent as the information boundary between the
investigator and the verifier." Cite this in the CVSS-for-AI paper introduction.

**VERITAS is Career rail, not Research rail.** The CCS 2027 paper on constraint inflation
in NIDS is the publication anchor. Do not let VERITAS architecture work eat that clock.
VERITAS feeds the Research rail only as infrastructure for the through-line argument.
