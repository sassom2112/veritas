# ADVERSA — Adversarial Forensic Investigation Framework

**A dual-agent AI that autonomously investigates Windows disk images for evidence of compromise.
A Triage Agent hunts for artifacts. A Forensic Auditor independently challenges every finding.
Only what survives physical verification makes it into the report.**

Built for the **SANS FIND EVIL! Hackathon 2026** — a competitive digital forensics challenge where
participants investigate real Windows disk images to identify attacker techniques, lateral movement,
and persistence across a multi-host environment.

---

## Why Two Agents?

LLMs hallucinate. In forensics, a hallucinated finding is a false accusation.

ADVERSA enforces a rule borrowed from adversarial ML: **the model that finds evidence and the model
that verifies it must be independent**. The Forensic Auditor has no access to the Triage Agent's
reasoning — it re-runs its own tool calls from scratch and demands to see bytes on disk.
On the live case data, this caught 2 false positives the triage pass scored as HIGH confidence.

Detection rules are trained the same way: a **Red Agent** generates evasion variants of known
attack patterns, a **Blue Agent** learns to catch them. Over 3,000 iterations on ~49,500 real
Windows Sysmon events, the system self-corrected from **10% → 75% detection rate with zero
human intervention** after hitting a domain gap on real telemetry.

---

## What It Does

![ADVERSA Layered Forensic Architecture Stack](docs/adversa-architecture.png)

Detection is backed by **11 operational rules** trained via an adversarial Red vs Blue loop on
**~49,519 real Mordor/OTRF Sysmon events** across 9 MITRE ATT&CK techniques.

---

## Quick Start

### Prerequisites

```bash
# Ubuntu / SANS SIFT Workstation (recommended)
python3 -m venv ~/adversa-env
source ~/adversa-env/bin/activate
pip install anthropic mcp matplotlib numpy

export ANTHROPIC_API_KEY="sk-ant-..."
```

The framework requires access to a **mounted Windows disk image** at a path like `/mnt/hostname`.
It reads the filesystem using standard SIFT/Sleuth Kit tools — no write access to evidence is needed.

### Run a full investigation

```bash
# Terminal 1 — start the forensic MCP tool server
python3 custom-agent/sift_server.py

# Terminal 2 — run the adversarial pipeline
python3 custom-agent/investigate.py /mnt/tdungan
```

What you will see:
- **Pass 1** — deterministic IOC sweep (~5 s), scored immediately
- **Pass 2** — 75-call Claude agentic loop, deep technique-specific scans
- **Forensic Auditor** — independent re-verification of every finding
- HTML report written to `reports/<hostname>-report.html`
- IOCs auto-propagated to the next `investigate.py` run (campaign mode)

### Investigate multiple hosts (campaign mode)

```bash
# IOCs from completed hosts are automatically loaded for subsequent runs
python3 custom-agent/investigate.py /mnt/nromanoff
python3 custom-agent/investigate.py /mnt/nfury       # uses nromanoff IOCs
python3 custom-agent/investigate.py /mnt/controller  # uses both
```

### Fast triage only (no API key, < 10 seconds)

```bash
python3 fast-triage/fast_triage.py /mnt/hostname
# Deterministic IOC sweep, prints confidence score and matched signals
# Auto-escalates to full pipeline if score ≥ 30
```

---

## Components

| File | Purpose |
|------|---------|
| `custom-agent/investigate.py` | **Main entry point** — orchestrates full pipeline |
| `custom-agent/blue_agent.py` | Triage Agent — two-pass SIFT + Claude agentic investigator |
| `custom-agent/auditor_agent.py` | Forensic Auditor — adversarial re-verification loop |
| `custom-agent/sift_server.py` | MCP tool server — 4-layer security, forensic tool access |
| `custom-agent/html_report.py` | HTML report generator (exec summary, IOC table, transcripts) |
| `custom-agent/extract_iocs.py` | IOC extractor — C2 IPs, file hashes, accounts from findings |
| `custom-agent/brain.py` | ASL training loop — Red vs Blue adversarial signal learning |
| `custom-agent/mordor_agent.py` | Red Agent — draws real Mordor Sysmon events, generates evasions |
| `custom-agent/export_patterns.py` | Exports trained patterns → `operational_rules.json` + Sigma rules |
| `custom-agent/pattern_db.py` | SQLite pattern store — versioned signals with hit/miss counters |
| `fast-triage/fast_triage.py` | Deterministic triage — no LLM, sub-10 s |
| `adversa.sh` | One-command launcher with API key prompt |

---

## Pre-trained Rules

`reports/operational_rules.json` ships with **11 operational rules** covering:

| Technique | Coverage |
|-----------|----------|
| T1003.001 | LSASS memory dump (mimikatz, spinlock, sekurlsa) |
| T1071.001 | C2 web protocol (IP-based beaconing, /ads/ URI pattern) |
| T1569.002 | Service execution (PsExec, PSEXESVC, sc.exe create) |
| T1547.001 | Registry run key persistence (dllhost\\svchost) |
| T1087.001 | Local account enumeration |
| T1204.002 | User execution of malicious file |
| T1036.005 | Masquerading via renamed system binaries |
| + 4 more  | Credential access, lateral movement, exfiltration |

`reports/sigma_rules/` contains adversarially-validated Sigma rules exportable to any SIEM.

### Retrain from scratch (~30 min)

```bash
# Download Mordor datasets first (see DATASET.md)
python3 custom-agent/brain.py            # adversarial training, 3000 iterations
python3 custom-agent/export_patterns.py  # → operational_rules.json + sigma_rules/
```

---

## Results

### Adversarial Training — Self-Correction Over 3,000 Iterations

The system hit a domain gap at iteration ~10 when switching from synthetic to real Sysmon
telemetry — detection collapsed from ~100% to 10%. The Red vs Blue loop autonomously recovered
to 75% with no human intervention.

![Training progression](reports/training_graphs.png)

| Metric | Value |
|--------|-------|
| Training iterations | 3,000 |
| Detection rate (recall) | 75% |
| Precision | 69% |
| F1 score | 0.72 |
| MITRE techniques covered | 9 |
| Red evasion variants evolved | 1,245 |
| Signals learned autonomously | 83 |

### Live Investigation — SANS FIND EVIL! 2026 Case Data

| Host | Confirmed Techniques | Score | Verdict |
|------|---------------------|-------|---------|
| tdungan | T1003.001, T1204.002, T1059 | 100/100 | HIGH |
| nfury | T1003.001, T1087.001 | 95/100 | HIGH |
| controller | T1003.001 | 50/100 | HIGH (2 FPs caught by Auditor) |

The controller result is the most illustrative: the Triage Agent scored 145, flagging three
techniques. The Forensic Auditor refuted two (legitimate svchost in WinSxS, user profile
directory traversal). Final confirmed score: 50. One real finding, zero false accusations.

See [ACCURACY.md](ACCURACY.md) for full iteration progression. See [SUBMISSION.md](SUBMISSION.md)
for the full case walkthrough with terminal output.

---

## MCP Tool Server Security

![ADVERSA Guardrails — Anti-Hallucination Trust Chain & MCP Security Boundary](docs/adversa-guardrails.png)

`sift_server.py` implements a **4-layer validator** before executing any forensic command:

1. Hard-blocked strings (`rm`, `dd`, `mkfs`, overwrite patterns)
2. Binary allowlist (only approved SIFT tools can execute)
3. Quote-aware pipe parser (no command injection through pipes)
4. Redirect guard (`>` writes verified to land in `reports/` only)

Architecture beats prompts — evidence modification is structurally impossible, not prompt-dependent.

---

## Datasets

Mordor/OTRF real Windows Sysmon telemetry is not included in this repo (1.3 GB).
Download instructions: [DATASET.md](DATASET.md)

---

## License

MIT
