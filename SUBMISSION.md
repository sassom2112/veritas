---
title: Try It Out
nav_order: 3
permalink: /submission
---

# Try It Out

VERITAS runs on a SANS SIFT workstation against mounted Windows disk images. There is no hosted demo — the tool calls real forensic binaries (`vol.py`, `fls`, `rip.pl`, `grep`) directly against evidence files. That's the point.

---

## Live Investigation Reports

Four fully validated pipeline runs. Every Auditor challenge, tool call, and verdict is interactive and browsable.

[View nfury Investigation Report](/nfury){: .btn .btn-primary .mb-4 }
[View tdungan Investigation Report](/tdungan){: .btn .mb-4 }
[View nromanoff Investigation Report](/nromanoff){: .btn .mb-4 }
[View rocba Investigation Report](/rocba){: .btn .mb-4 }

**nfury:** 19 detected · 15 confirmed · 4 refuted · 16 min · $14  
**tdungan (campaign mode):** 17 detected · 13 confirmed · 4 refuted · 15 min · $14  
**nromanoff:** 7 detected · 3 confirmed · 4 refuted · 15 min · $14  
**rocba (attacker C2 node):** 5 detected · 1 confirmed · 4 refuted · 23 min · ~$14  
**Total: 32 confirmed across 48 detected · 16 correctly refuted · exactly 4 refutals per host**

---

## Setup

```bash
# SANS SIFT workstation (Ubuntu) recommended
python3 -m venv ~/adversa-env && source ~/adversa-env/bin/activate
pip install anthropic mcp matplotlib numpy

export ANTHROPIC_API_KEY="sk-ant-..."
```

Requires a Windows disk image mounted read-only at a path like `/mnt/hostname`.

---

## Full adversarial pipeline

```bash
# Terminal 1
python3 custom-agent/sift_server.py

# Terminal 2
python3 custom-agent/investigate.py /mnt/hostname
```

Runs Triage → Auditor → HTML report.

**Campaign mode** — declare prior hosts explicitly to propagate confirmed IOCs:

```bash
python3 custom-agent/investigate.py --case ~/cases/nfury
python3 custom-agent/investigate.py --case ~/cases/tdungan nfury
python3 custom-agent/investigate.py --case ~/cases/controller nfury tdungan
```

Host names resolve to `reports/<host>-iocs.json`. Explicit declaration required — IOCs are never injected automatically, preventing cross-campaign contamination.

---

## Rebuild signal weights

```bash
# Recalibrate corpus weights from MalwareBazaar + HybridAnalysis
MB_API_KEY=your_key HA_API_KEY=your_key python3 custom-agent/build_corpus.py --limit 100
python3 custom-agent/compute_weights.py       # → data/calibrated_weights.json

# Retrain Sysmon ASL (requires Mordor datasets — see DATASET.md)
python3 custom-agent/brain.py                 # ~30 min, 3000 iterations
python3 custom-agent/export_patterns.py       # → operational_rules.json
```

---

## Output files

| File | What it contains |
|------|-----------------|
| `reports/hostname-report.html` | Full investigation report — exec summary, IOC table, Auditor transcript |
| `reports/hostname-investigation.json` | Confirmed / inconclusive / refuted techniques, adjusted score |
| `reports/hostname-auditor-transcript.json` | Every Auditor challenge, round-by-round, with tool output and reasoning |
| `reports/operational_rules.json` | Sysmon ASL operational rules — ships with the repo, no training required to use |
| `reports/sigma_rules/*.yml` | Sigma detection rules, adversarially validated |
