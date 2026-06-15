# Handoff — future/cross-layer-verification (2026-06-14)

## Current task

Three sprints complete and committed. Discussing Sprint 4 (model routing) next — reduce per-host
cost from ~$14 to ~$8 by routing synthesis turns to claude-haiku-4-5-20251001.

---

## What was built this session (all committed, branch clean)

| Commit | Sprint | What |
|---|---|---|
| `82ea667` | Sprint 1 | AGENTS.md + verifier.py + contracts.py + cross_verifier.py + investigate.py + doc pass |
| `2297417` | Sprint 2 | evals/eval_output.py + eval_trajectory.py + ground_truth/nfury.json + rocba.json + run_evals.sh |
| `38b847e` | Sprint 3 | skills/ (10 technique playbooks) + _load_skill() wired into auditor_agent._challenge_round() |

**Smoke test results (run_evals.sh):**
- PASS [nfury] output eval — 15 confirmed, 4 refuted, 0 inconclusive
- PASS [rocba] output eval — 1 confirmed, 4 refuted, 0 inconclusive
- PASS [nfury] trajectory eval — 5 checks
- PASS [rocba] trajectory eval — 4 checks
- All Python files compile clean (py_compile on 7 files)

---

## Exact next step

**Sprint 4 — Model routing:**

Two env vars, two files. Both need the same change pattern:

**`custom-agent/auditor_agent.py`:**
- Line `model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6')` is used in `_challenge_round()` at the `self.client.messages.create(...)` call (line ~490)
- Synthesis turns are where the model has tool results in hand and just needs to emit a text verdict. In the Auditor, every call is investigation reasoning — no synthesis-only turn exists. Keep `VERITAS_MODEL` here.

**`custom-agent/verifier.py`:**
- `_verify_one()` makes two distinct call types:
  1. Investigation turns (tool_choice='any', forces a tool call) — keep `VERITAS_MODEL`
  2. The final forced `record_verdict` call — this is a synthesis turn, use `VERITAS_SYNTHESIS_MODEL`
- Locate the `messages.create(...)` call in `_verify_one()`. The synthesis turn is identified by `tool_choice={'type': 'any'}` on the `_RECORD_VERDICT_TOOL` call — it already forces the tool call, so haiku is sufficient
- Add: `_SYNTHESIS_MODEL = os.environ.get('VERITAS_SYNTHESIS_MODEL', 'claude-haiku-4-5-20251001')`
- Add: `_INVESTIGATION_MODEL = os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6')`
- Use `_SYNTHESIS_MODEL` for the `record_verdict` forced call, `_INVESTIGATION_MODEL` for tool-use investigation turns

**`custom-agent/blue_agent.py` and `memory_agent.py`:**
- Both have synthesis turns: the `record_finding` forced tool call after investigation
- Same pattern: `_SYNTHESIS_MODEL` for that single forced call, `_INVESTIGATION_MODEL` for all investigation turns
- Grep for `record_finding` in both files to find the synthesis call site

After Sprint 4: run `bash evals/run_evals.sh` to confirm output eval still passes — if routing to haiku didn't change verdicts, the 4/4 pass is the green light.

---

## Open questions / blockers

- **Architecture docs are wrong on this branch:** `README.md`, `architecture.md`, `the-game.md`,
  `index.md`, `SUBMISSION.md` all describe the 3-phase main branch pipeline (Disk + Memory → Auditor).
  The cross-layer branch has a 4-phase pipeline (Disk + Memory → Same-layer Verifier [PRIMARY GATE]
  → Cross-layer Corroborator → adjudicate). These need complete rewrites before this branch
  merges to main. Sprints 4-6 first, then doc rewrite.

- **Missing ground truth:** No `reports/tdungan-auditor-transcript.json` or
  `reports/nromanoff-auditor-transcript.json` in the repo. Add
  `evals/ground_truth/tdungan.json` and `nromanoff.json` once those pipeline runs are saved.
  `run_evals.sh` picks them up automatically.

- **Hackathon deadline June 15, 2026:** Demo video (5 min, live terminal, audio narration) +
  Devpost submission (8 required fields) still required. Hackathon runs off `main` branch
  (3-phase pipeline, stable). Independent of sprint work but must not be forgotten.

- **Sprint 3 skill coverage:** 10 skills cover the nfury/rocba ground truth. Techniques from
  tdungan and nromanoff (T1566 phishing, T1003.001 LSASS, T1021.002 SMB) have no playbooks yet.
  Add them when those transcripts are available.

---

## Relevant context

- **Information boundary:** `_build_verifier_message()` in `custom-agent/verifier.py` is the
  sole handoff construction point. Only `technique_id`, `tool_output[:1500]`, `artifact_hint`
  cross. Do not add investigator reasoning here.

- **same_verdict drives final; cross_verdict annotates:** `_final()` in `cross_verifier.py`.
  Phase 3 CONTRADICTED cannot rescue Phase 2 REFUTED.

- **INCONCLUSIVE ≠ REFUTED:** Timeout, budget exhaustion, insufficient output → INCONCLUSIVE.
  Only contradicting evidence → REFUTED. rocba T1055 Round 1 timeout is the canonical example.

- **Skill injection location:** `_load_skill(finding_id)` is called inside `_challenge_round()`
  in `auditor_agent.py` after `p2_block` is constructed and before `messages` is built. The
  skill content is added to the per-technique user message, not to `_AUDITOR_SYSTEM`. This means
  each challenge round for that technique sees the playbook — intentional, since multi-round
  techniques (T1055 timeout → retry) need the playbook on Round 2 too.

- **Skills directory:** `skills/` at repo root. Path computed in `auditor_agent.py` as
  `_SKILLS = os.path.normpath(os.path.join(_HERE, '..', 'skills'))` where `_HERE` is
  `os.path.dirname(os.path.abspath(__file__))`. Glob pattern: `{technique_id}-*.md`.

- **Python version:** 3.8.10 on SIFT workstation. Use `from __future__ import annotations`
  for modern type hints. Both eval scripts already have this.

- **Do NOT merge to main** until Sprint 2 eval harness passes AND architecture docs are
  rewritten for the 4-phase pipeline.

- **Branch:** `future/cross-layer-verification`. `main` is hackathon submission (3-phase, stable).

- **SIFT workstation:** `192.168.1.71` — ping before assuming online.

- **Epistemic through-line (canonical):** `/home/username/research/epistemic-through-line.md`
  "A verification result is only as independent as the information boundary between the
  investigator and the verifier."
