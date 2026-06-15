# Handoff — future/cross-layer-verification (2026-06-14)

## Current task

All six sprint backlog items are committed and green on `future/cross-layer-verification`.
The immediate next action is the hackathon demo video — deadline June 15, 2026 (tomorrow).

---

## What's been tried

All six sprints completed this session. Every commit is clean and `bash evals/run_evals.sh`
returns 4/4 pass + 2 conditional skips (metrics, waiting on pipeline run).

| Commit | Sprint | What |
|---|---|---|
| `82ea667` | Sprint 1 | `AGENTS.md` (148-line harness contract) + `verifier.py` (Phase 2 same-layer blind replication) + `contracts.py` (`SameLayerVerdict`, updated `FinalTechniqueResult`) + `cross_verifier.py` (same_verdict primary gate) + `investigate.py` (4-phase orchestration) + doc consistency pass |
| `2297417` | Sprint 2 | `evals/` — output eval, trajectory eval, ground truth for nfury/rocba, `run_evals.sh` regression gate |
| `38b847e` | Sprint 3 | `skills/` — 10 per-technique playbooks; `_load_skill()` wired into `auditor_agent._challenge_round()` |
| `3d4ef6c` | Sprint 4 | Model routing in `verifier.py` — `_INVESTIGATION_MODEL` (sonnet) vs `_SYNTHESIS_MODEL` (haiku) for `record_verdict` forced call; fixed latent Python 3.8 `str | None` bug with `from __future__ import annotations` |
| `9670944` | Sprint 5 | `metrics.py` (`Metrics` class, pricing dict, phase timing); `contracts.py` (`PhaseTelemetry`, `HostAuditManifest`); metrics wired into `verifier.py`, `cross_verifier.py`, `investigate.py`; cost gate before Phase 3 (`TARGET_MAX_COST_USD = 20.0`); audit manifest written to `reports/{host}-audit-manifest.json`; `evals/eval_metrics.py` + conditional check in `run_evals.sh` |
| `80bde74` | Sprint 6 | INCONCLUSIVE feedback loop in `verifier._verify_one()` — `MAX_RETRY_CALLS = 2`, `_TIMEOUT_SIGNALS` tuple, `all_tool_outputs` accumulator, retry block between main while loop and forced verdict; timeout path → PID-targeted retry hint; budget-exhaustion path → narrowed artifact hint; retry calls tagged `phase_2_verify_retry` in metrics |

---

## Exact next step

### IMMEDIATE — Hackathon demo video (June 15, 2026 deadline)

The hackathon submission runs off **`main` branch** (3-phase pipeline, stable). Do NOT demo
from `future/cross-layer-verification`.

```bash
# 1. Confirm SIFT workstation is online
ping 192.168.1.71

# 2. Switch to main for the demo
git checkout main

# 3. Confirm nfury case is mounted
ls /mnt/nfury/Windows/System32/

# 4. Run the full pipeline (live on camera)
python3 custom-agent/investigate.py --case /cases/nfury

# 5. Open the HTML report for the payoff shot
open reports/nfury-report.html   # or xdg-open on Linux
```

Demo script (5 min, audio narration):
1. (0:00–0:30) Show the problem: LLMs hallucinate forensic findings. One command.
2. (0:30–1:30) Show Phase 1+2 running — terminal output, tool calls, triage flags
3. (1:30–2:30) Show the Auditor challenging each finding — CONFIRMED vs REFUTED live
4. (2:30–3:15) **Self-correction beat — T1071.001:** narrate that the Memory Agent flagged
   active C2 (show the triage output showing T1071.001 in the findings list). Then show the
   Auditor's verdict: ran windows.netscan independently, read 432 connection records, every
   established connection resolved to CDN, returned REFUTED. Say explicitly: "The system
   caught its own investigator and overrode the finding based on physical bytes."
5. (3:15–4:15) Show the HTML report — 15 confirmed, 4 refuted, every finding cited to artifact
6. (4:15–5:00) Show the 4-refutal pattern — same class of memory noise dismissed on every host,
   explain that discriminating behavior (not just confirmations) is the proof the game works

Devpost submission needs 8 fields — check hackathon page for exact requirements.

### AFTER DEMO — Architecture doc rewrite (before merge to main)

`README.md`, `architecture.md`, `the-game.md`, `index.md`, `SUBMISSION.md` all describe
the 3-phase main-branch pipeline. The cross-layer branch is a 4-phase pipeline:

```
Phase 1: Disk Agent + Memory Agent (parallel, disjoint tool grants)
Phase 2: Same-layer Verifier (PRIMARY GATE — blind replication, structural info boundary)
Phase 3: Cross-layer Corroborator (bonus, CONFIRMED claims only)
Phase 4: Adjudication (same_verdict drives final, cross_verdict annotates)
```

Every doc that says "Disk Agent + Memory Agent → Auditor" needs to become this 4-phase
description. The "Two Players / Three Players" framing in `the-game.md` needs to become
a "Four Phases" framing. This is a significant rewrite — do not merge to main until it is done.

---

## Open questions / blockers

- **Phase 1 token tracking is zero.** `metrics.start_phase('phase_1_disk')` and
  `metrics.start_phase('phase_1_memory')` record wall-clock timing but 0 token counts
  because `blue_agent.py` and `memory_agent.py` are not wired to the `Metrics` instance.
  The cost gate only reflects Phase 2+3 spend. Correct conservative behavior — but
  `{host}-audit-manifest.json` will show `phase_1_disk.input_tokens: 0`. Follow-on work:
  add optional `metrics` param to `DiskAgent.investigate()` and `mem_investigate_layered()`.

- **Missing ground truth for tdungan and nromanoff.** No `reports/tdungan-auditor-transcript.json`
  or `reports/nromanoff-auditor-transcript.json` in the repo. Once pipeline runs for those
  hosts are saved, add `evals/ground_truth/tdungan.json` and `nromanoff.json` —
  `run_evals.sh` picks them up automatically, no code changes needed.

- **Merge gate not cleared.** `future/cross-layer-verification` must NOT merge to `main`
  until: (1) architecture docs rewritten for 4-phase pipeline, (2) Sprint 2 evals pass on
  the new pipeline's output (not just saved transcripts from the old 3-phase run).

- **Audit manifest eval is conditional.** `eval_metrics.py` only runs if
  `reports/{host}-audit-manifest.json` exists. The manifest is only produced by
  `run_cross_layer()` in `investigate.py` — the new 4-phase path. Running the old
  `run_investigation()` (main branch) does not produce a manifest.

- **Hackathon Devpost fields.** 8 required fields — check the submission page. Likely:
  project name, description, tech stack, demo video URL, GitHub repo URL, team members,
  category, and one more. The live investigation reports at `reports/nfury-report.html`
  etc. should be linked or embedded.

---

## Relevant context

- **Branch discipline:** `main` = hackathon submission (3-phase, stable, do not touch before demo).
  `future/cross-layer-verification` = 6-sprint engineering run, all committed, evals green.

- **Information boundary is structural.** `_build_verifier_message()` in `custom-agent/verifier.py`
  is the sole handoff construction point. Only `technique_id`, `tool_output[:1500]`,
  `artifact_hint` cross. Investigator reasoning never passes through. Do not add context here.

- **same_verdict drives final; cross_verdict annotates.** `_final()` in `cross_verifier.py`.
  Phase 3 CONTRADICTED cannot rescue Phase 2 REFUTED.

- **INCONCLUSIVE ≠ REFUTED.** Timeout, budget exhaustion, insufficient output → INCONCLUSIVE.
  Only contradicting evidence → REFUTED. `MAX_RETRY_CALLS = 2` grants extra calls on
  INCONCLUSIVE before the forced verdict; if those also fail, INCONCLUSIVE is final.

- **VERITAS_LAYER enforcement is at the subprocess level.** Binary allowlist in
  `sift_server.py` reads the env var on import. Do not move this to a prompt instruction.

- **Python 3.8.10 on SIFT workstation.** All files that use modern type hints need
  `from __future__ import annotations`. Currently done: `verifier.py`, `cross_verifier.py`,
  `contracts.py`, `metrics.py`, `evals/eval_output.py`, `evals/eval_trajectory.py`,
  `evals/eval_metrics.py`. Not done: `blue_agent.py`, `memory_agent.py`, `auditor_agent.py`
  (those files have not been touched for 3.8 compat this session).

- **Pricing vectors in `custom-agent/metrics.py`.** Approximate 2026 rates:
  sonnet-4-6 $3/$15 per MTok, haiku-4-5 $0.80/$4 per MTok. Verify against current
  Anthropic pricing page before citing cost numbers in the Devpost submission.

- **Epistemic through-line (canonical).** `/home/username/research/epistemic-through-line.md`
  "A verification result is only as independent as the information boundary between the
  investigator and the verifier." This argument survives into the CCS 2027 paper on
  constraint inflation. Do not lose it in architectural rewrites.

- **SIFT workstation.** `192.168.1.71` — ping before assuming online.

- **nfury ground truth.** 15 confirmed, 4 refuted. `reports/nfury-auditor-transcript.json`.
  rocba: 1 confirmed, 4 refuted. `reports/rocba-auditor-transcript.json`.
