# ADVERSA — Autonomous Windows Forensic Investigation

A three-phase pipeline for dead-disk and memory forensics on Windows images. Deterministic triage,
agentic deep investigation, adversarial audit. Every confirmed finding is backed by a physical
artifact on disk — not model confidence.

Built for the **SANS FIND EVIL! Hackathon 2026**.

---

## The Problem

A senior examiner takes 48 hours to fully characterize a compromised Windows host. A coordinated
intrusion hits 50 endpoints simultaneously. The math does not work. The bottleneck is not
attacker speed — once the image is acquired, the bits are frozen. The bottleneck is
**Time-to-Understanding**: how long until a human investigator knows what happened.

ADVERSA targets that number. A full disk and memory investigation runs in 17 minutes for $14 in
API cost. It can run on N machines in parallel overnight. A human analyst reviews confirmed
findings, not raw tool output.

The second problem is hallucination. LLMs find evidence because they are trained to be helpful.
On the nfury image, the triage pass scored 9 techniques. The adversarial auditor confirmed 2 and
refuted 7. Without independent verification, 7 false accusations would have entered the report.
Prompt instructions do not fix this. Architectural separation does.

---

## Pipeline

```
Disk image + memory dump
         │
         ▼
   Pass 1 — Deterministic scan (~25 SIFT commands, <60 s)
   Corpus-calibrated log-odds scoring across 9 MITRE techniques
         │
         ▼
   Pass 2 — Agentic investigation (75-call budget, Claude Sonnet)
   Sequences tool calls like a senior examiner: event logs → prefetch →
   registry hives → MFT → shellbags → hash verification
   Receives raw artifacts only — no Pass 1 score, no technique labels
         │
   Memory — Volatility 3 in parallel
   Process injection, hollowing, rootkits invisible on disk
         │
         ▼
   Forensic Auditor (up to 5 rounds × 2 tool calls per technique)
   Receives finding list only — no access to prior reasoning
   Mandate: assume every finding is a false positive until the
   filesystem proves otherwise
         │
         ▼
   IOC extraction → HTML report → campaign propagation
```

All tool execution passes through a 4-gate validator (`sift_server.py`) before any subprocess
call. Evidence modification is architecturally impossible — not prompt-dependent.

---

## Detection Signal Stack

Two sources feed Pass 1 scoring. Both are transparent substring matches — no black-box weights.

**Corpus-calibrated weights** (`data/calibrated_weights.json`)

Log-odds ratios derived from 800+ labeled malware samples (MalwareBazaar + HybridAnalysis).
For each `(technique, signal)` pair:

```
log_odds = log2( (p_malware + 0.05) / (p_benign + 0.05) )
weight   = normalize(log_odds) → [0, 1]
```

Cross-technique tokens capped at 0.2 (IDF-equivalent). Base signals from confirmed cases
floored at 0.5. Every weight is traceable to a source sample.

Covers 9 techniques: T1003.001/002, T1059.001, T1071.001, T1087.001, T1547.001, T1548.002,
T1560.001, T1569.002.

**Sysmon ASL operational rules** (`reports/operational_rules.json`)

Trained adversarially on 49,519 real Windows Sysmon events (OTRF Mordor datasets). A Red Agent
generates evasion variants; a Blue Agent extracts discriminating field values from misses. Rules
are literal substrings from real telemetry — no hand-authored patterns.

Domain gap exists: Sysmon signals reference event fields absent from disk forensic output. These
rules supplement corpus weights but do not replace them on disk artifacts.

---

## Results

One full-pipeline case (disk + memory, calibrated weights, current auditor):

**nfury** — APT1-era intrusion, httppump C2 (199.73.28.114/ads/), attacker account `vibranium`

| Phase | Score | Techniques |
|---|---|---|
| Triage (disk) | 100/100 | 9 detected |
| Triage (memory) | 100/100 | overlapping |
| Auditor adjusted | 70/100 | 2 confirmed, 7 refuted |
| Verdict | HIGH | Active compromise confirmed |

Confirmed: **T1003.002** (SAM credential dump), **T1055** (process injection via a.exe loader)

One of the 7 auditor refutals (T1569.002, PsExec) was a validator bug — `'service '` hard-block
was rejecting EventID 7045 grep commands. Fixed and committed; re-run pending.

Earlier pipeline versions (pre-calibrated weights, pre-auditor fix) ran on controller and tdungan.
Those results are in `SUBMISSION.md` and are not directly comparable to the current system.

---

## Security Boundary

![ADVERSA Guardrails](docs/adversa-guardrails.png)

Four gates, enforced in code before any subprocess call:

1. **Hard-blocked strings** — 22 tokens: destructive ops (`shred`, `mkfs`, `fdisk`), exfil
   (`wget`, `curl`, `nc`, `ssh`), privilege escalation (`sudo`, `pkexec`), injection
   (`$(`, `` ` ``, `${`, `system(`), specific service control verbs
2. **Binary allowlist** — 53 approved SIFT forensic tools. Unknown binaries rejected
   unconditionally. `sed` excluded — its `-e` flag passes the pattern space to the shell.
3. **Quote-aware pipeline parser** — each pipe segment validated independently. Handles
   `grep -iE '(http|https|ftp)'` without splitting on `|` inside quoted arguments.
4. **Write-target guard** — all `>`, `>>`, and `tee` targets resolved with `os.path.realpath`
   and must land inside `reports/`. Symlink traversal and `../` injection fail at the math level.

`audit_log.jsonl` is appended atomically via `os.open + os.write` before every subprocess call.
Blocked commands log `blocked_reason`. The audit trail cannot be overwritten through a tool call.

Evidence mounts are `ro,norecovery` at the kernel level. The application validator is a second
layer, not the first.

---

## Quick Start

```bash
git clone https://github.com/sassom2112/adversa.git
cd adversa
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."

# Terminal 1 — forensic tool server
python3 custom-agent/sift_server.py

# Terminal 2 — full investigation
python3 custom-agent/investigate.py /mnt/hostname

# Fast triage only — no API key, <10 s
python3 fast-triage/fast_triage.py /mnt/hostname
```

Requires a mounted Windows disk image. The framework reads via standard SIFT/Sleuth Kit tools —
no write access to evidence.

### Campaign mode

```bash
python3 custom-agent/investigate.py /mnt/nromanoff
python3 custom-agent/investigate.py /mnt/nfury reports/nromanoff-iocs.json
python3 custom-agent/investigate.py /mnt/controller reports/nromanoff-iocs.json reports/nfury-iocs.json
```

Each run writes `reports/<hostname>-iocs.json`. Pass prior IOC files explicitly to propagate
confirmed indicators across the investigation. `investigate.py` auto-detects IOC files in
`reports/` if none are passed.

### Rebuild signal weights

```bash
# Collect malware corpus from MalwareBazaar + HybridAnalysis
MB_API_KEY=your_key HA_API_KEY=your_key python3 custom-agent/build_corpus.py --limit 100

# Recompute log-odds weights
python3 custom-agent/compute_weights.py

# Retrain Sysmon ASL (requires Mordor datasets — see DATASET.md)
python3 custom-agent/brain.py
python3 custom-agent/export_patterns.py
```

---

## Components

| File | Role |
|---|---|
| `custom-agent/investigate.py` | Orchestrator — runs full pipeline end to end |
| `custom-agent/blue_agent.py` | Triage agent — Pass 1 scoring + Pass 2 agentic loop |
| `custom-agent/auditor_agent.py` | Forensic auditor — adversarial re-verification |
| `custom-agent/sift_server.py` | MCP tool server — 4-gate validator, subprocess execution |
| `custom-agent/memory_agent.py` | Memory analysis — Volatility 3 parallel path |
| `custom-agent/extract_iocs.py` | IOC extraction — C2 IPs, filenames, accounts |
| `custom-agent/html_report.py` | HTML report with exec summary, IOC table, transcripts |
| `custom-agent/build_corpus.py` | Corpus collection — MalwareBazaar + HybridAnalysis |
| `custom-agent/compute_weights.py` | Weight calibration — log-odds from corpus |
| `custom-agent/brain.py` | Sysmon ASL training — Red/Blue adversarial loop |
| `custom-agent/export_patterns.py` | Exports brain state → `operational_rules.json` |
| `fast-triage/fast_triage.py` | Deterministic triage — no LLM, sub-10 s |

---

## Honest Limitations

**One validated full-pipeline case.** nfury is the only image run through the current system
end-to-end. Earlier results on controller and tdungan used a different version.

**9 techniques in corpus weights.** Coverage is real but not comprehensive. Techniques outside
this set fall back to base signals and Sysmon ASL rules, which have lower precision on disk
artifacts.

**Sysmon ASL domain gap.** Signals learned from Windows event logs do not transfer cleanly to
SIFT disk tool output. They fire on overlapping techniques but should not be treated as
disk-validated.

**Auditor refutation rate is high by design.** On nfury: 9 detected, 2 confirmed. This is the
system working correctly — the triage net is wide, the auditor is strict. One confirmed finding
backed by physical evidence is more useful than nine findings backed by model confidence.

**$14/run, ~17 minutes.** Cheap relative to analyst time. Not free.

---

## License

MIT
