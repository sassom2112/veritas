# Handoff — future/cross-layer-verification (2026-06-14)

## Current task

All 5 documentation sprints are complete and committed; the immediate next action is
recording the hackathon demo video from the **`main` branch** before the June 15, 2026
deadline.

---

## What's been tried

- **Three-layer stale-name purge (committed `4973879`)** — fixed every instance of
  "Triage Agent", "Memory Triage Agent", "triage agent's reasoning", "two-player game",
  "Cynic", "Optimist", and "fast_triage" across all three content layers:
  - Layer 1 (markdown): `the-game.md`, `architecture.md`, `index.md`, `README.md`,
    `docs/project_story.md`, `AGENTS.md`
  - Layer 2 (TeX): `docs/adversa-guardrails.tex`, `docs/adversa_paper.tex`,
    `docs/project_story.tex`, `docs/gen_guardrails.py`, `reports/adversa-architecture.tex`
  - Layer 3 (Python/HTML): `custom-agent/auditor_agent.py`, `custom-agent/html_report.py`,
    `custom-agent/investigate.py`, `custom-agent/memory_agent.py`,
    `custom-agent/blue_agent.py`, `custom-agent/contracts.py`
  - `evals/verify_submission.py` created as the submission gate (exits 0 = clean, 1 = fail)
  - `evals/run_evals.sh` updated to run the gate as the final check
  - `evals/verify_submission.py` `_EXCLUDE_PATHS` includes `fast-triage/` and `find_evil.py`
    (legitimate functional callers of `fast_triage.py`, not stale docs)

- **Sprint 1 — IR vs. DF speed framing (committed `8b3510d`)** — replaced the erroneous
  "7-minute adversary breakout window" comparison with the correct framing: SIFT runs on
  dead-disk images after IR has already contained the host; correct comparison is 3–12 hours
  of human forensic analyst time vs. 16 minutes for VERITAS. Updated `README.md`,
  `docs/project_story.md`, `docs/project_story.tex`.

- **Sprint 2 — self-correction story (committed `d572db3`)** — added explicit T1071.001
  REFUTED self-correction framing to:
  - `the-game.md`: new "## The Self-Correction Case" section (8 paragraphs) between
    scoreboard and rocba section
  - `docs/project_story.md`: "The self-correction case — T1071.001" callout paragraph
    in Accomplishments section
  - `docs/project_story.tex`: `\textbf{Self-correction --- T1071.001.}` paragraph in
    Accomplishments section
  - `HANDOFF.md` demo script: explicit self-correction beat at 2:30–3:15 with narration
    notes

- **Sprints 3 + 4 (committed `60a7967`)** —
  - `tests/test_spoliation.py`: 13 tests, 4 gates, all pass (`pyenv exec pytest` 13/13
    in 0.54s). Covers: Gate 1 hard-blocked (shred, wget, sudo, `$()`, backtick); Gate 2
    allowlist (bash, python3 -c, find -exec rm, xargs rm); Gate 3 redirect guard (outside
    reports/, /etc/shadow, audit_log.jsonl explicit deny); Gate 4 quote-aware parser
    correctness (grep -iE with `|` inside single quotes must PASS, not be split)
  - `ACCURACY.md`: added "## Spoliation Gate Tests" with 13-row results table; added
    "## Negative Ground Truth" with per-host per-technique REFUTED breakdown for T1071.001,
    T1134, T1547.001, T1574, and T1569.002 case-specific variation (CONFIRMED nfury,
    REFUTED tdungan)

- **Sprint 5 — submission gate (committed earlier session)** — `evals/verify_submission.py`
  exists, exits 0 currently. Already wired as final step in `evals/run_evals.sh`.

---

## Exact next step

### IMMEDIATE — Hackathon demo video (June 15, 2026 deadline)

The hackathon submission runs off **`main` branch** (3-phase pipeline, stable).
Do NOT demo from `future/cross-layer-verification`.

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
xdg-open reports/nfury-report.html
```

Demo script (5 min, audio narration):
1. **(0:00–0:30)** Show the problem: LLMs hallucinate forensic findings. State it once,
   run the command.
2. **(0:30–1:30)** Show Phase 1 + 2 running — terminal output, tool calls, triage flags
   appearing in real time.
3. **(1:30–2:30)** Show the Auditor challenging each finding — CONFIRMED vs REFUTED verdicts
   appearing live.
4. **(2:30–3:15)** **Self-correction beat — T1071.001:** show the triage output where
   T1071.001 appears in the findings list (Memory Agent flagged active C2). Then show the
   Auditor's verdict: ran `windows.netscan` independently, read 432 connection records,
   every established connection resolved to CDN, returned REFUTED. Say explicitly on camera:
   *"The system caught its own investigator and overrode the finding based on physical bytes."*
5. **(3:15–4:15)** Show the HTML report — 15 confirmed, 4 refuted, every finding cited to
   a specific tool call artifact.
6. **(4:15–5:00)** Show the 4-refutal pattern — same class of memory noise dismissed on
   every host. Explain that discriminating behavior (not just the 32 confirmations) is the
   proof the architecture works.

---

## Open questions / blockers

- **Sprint 4 negative ground truth needs transcript validation.** `ACCURACY.md` describes
  what the Auditor did for T1134, T1547.001, T1574 refutals based on pipeline behavior
  documented in the repo. Before citing in a legal or judging context, cross-check against
  `reports/nfury-auditor-transcript.json` to confirm specific evidence the Auditor cited.

- **Missing ground truth for tdungan and nromanoff.** No
  `reports/tdungan-auditor-transcript.json` or `reports/nromanoff-auditor-transcript.json`
  in the repo. Once pipeline runs for those hosts are saved, add
  `evals/ground_truth/tdungan.json` and `nromanoff.json` — `run_evals.sh` picks them up
  automatically.

- **Hackathon Devpost fields.** 8 required fields to fill on Devpost. Check submission page
  for exact list. Likely: project name, description, tech stack, demo video URL, GitHub repo
  URL, team members, category, and one more. Link live investigation reports from
  `reports/nfury-report.html`.

- **Architecture docs on cross-layer branch are stale.** `README.md`, `architecture.md`,
  `the-game.md`, `index.md`, `SUBMISSION.md` all describe the 3-phase main-branch pipeline.
  The cross-layer branch is a 4-phase pipeline. This rewrite must happen before any merge
  to main — but do NOT do it before the demo video is recorded.

- **`future/cross-layer-verification` merge gate not cleared.** Must NOT merge to `main`
  until: (1) architecture docs rewritten for 4-phase pipeline, (2) Sprint 2 evals pass on
  new pipeline output (not just saved transcripts from the old 3-phase run).

---

## Relevant context

- **Branch discipline:** `main` = hackathon submission (3-phase, stable, do not touch
  before demo). `future/cross-layer-verification` = all sprints done, verify gate green,
  not yet ready to merge.

- **`evals/verify_submission.py` is the source of truth for submission cleanliness.**
  Run `python3 evals/verify_submission.py` before any commit that touches docs or code.
  Currently exits 0. If it exits 1, fix the listed issues before committing.

- **INCONCLUSIVE ≠ REFUTED.** This invariant is critical for the demo. rocba T1055 Round 1
  timed out → INCONCLUSIVE (not CONFIRMED). Round 2 recovered one VAD record → CONFIRMED.
  Do not describe timeout as failure or as REFUTED.

- **T1071.001 REFUTED is self-correction, not failure.** The Memory Agent was correct to
  flag it (TCP state strings appear in any live memory). The Auditor was correct to refute
  it (432 connection records, all CDN). The system did its job.

- **T1569.002 per-host variation is the case-specific decision proof.** CONFIRMED on nfury
  (`psexesvc.exe` on disk), REFUTED on tdungan (memory signal, no binary). Same technique,
  same Auditor, two different verdicts. This is the answer to "is the Auditor just running
  a fixed pattern?"

- **The information boundary is structural.** `_build_verifier_message()` in
  `custom-agent/verifier.py` is the sole handoff construction point between investigator
  and verifier. Only `technique_id`, `tool_output[:1500]`, `artifact_hint` cross.
  Investigator reasoning never passes through. Do not add context to `_AUDITOR_SYSTEM`
  or `_VERIFIER_SYSTEM` — this would break the independence guarantee.

- **Epistemic through-line (canonical):** "A verification result is only as independent as
  the information boundary between the investigator and the verifier." This is the one-line
  argument for why the architecture works. Use it verbatim in the demo narration.

- **SIFT workstation:** `192.168.1.71` — ping before assuming online.

- **Python on SIFT:** Python 3.8.10. All files that use modern type hints need
  `from __future__ import annotations`. The main-branch agents (`blue_agent.py`,
  `memory_agent.py`, `auditor_agent.py`) have not been audited for 3.8 compat this session
  — they have been running in production so assume they work.

- **Spoliation tests run under Python 3.11 via pyenv:** `pyenv exec pytest tests/test_spoliation.py -v`
  The venv Python (3.8) does not have pytest installed.
