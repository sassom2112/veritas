---
title: VERITAS
nav_order: 1
description: Autonomous Windows forensic investigation with adversarial verification
---

# VERITAS
{: .fs-9 }

Autonomous Windows forensic investigation. Every confirmed finding backed by a physical artifact — not model confidence.
{: .fs-6 .fw-300 }

[How It Works](how-it-works){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Try It Out](submission){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/sassom2112/find-evil-2026){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## The one-line version

The Disk Agent and Memory Agent investigate in parallel on separate evidentiary layers. The Forensic Auditor challenges every finding independently from physical bytes. CONFIRMED requires a positive return value from a real forensic tool. Model confidence counts for nothing.

---

## Results — 4 hosts, SANS FIND EVIL! 2026 case data

| Host | Investigated | Confirmed | Refuted | Time | Cost |
|------|-------------|-----------|---------|------|------|
| nfury (10.3.58.6) | 19 candidates | **15** | **4** | 16 min | $14 |
| tdungan (10.3.58.7) | 17 candidates | **13** | **4** | 15 min | $14 |
| nromanoff (10.3.58.5) | 7 candidates | **3** | **4** | 15 min | $14 |
| rocba (192.168.1.5) — C2 node | 5 candidates | **1** | **4** | 23 min | ~$14 |
| **Total** | **48** | **32** | **16** | — | **< $60** |

Exactly 4 refutals per host across all four investigations. Every confirmed finding independently reproducible from the audit log with one shell command.

[View live investigation reports with full Auditor transcripts →](submission)

---

## Quick start

```bash
git clone https://github.com/sassom2112/find-evil-2026.git
cd find-evil-2026
python3 -m venv forensics_env
source forensics_env/bin/activate
pip install -r requirements.txt
```

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

```bash
# Terminal 1 — MCP forensic tool server
source forensics_env/bin/activate
python3 custom-agent/sift_server.py
```

```bash
# Terminal 2 — full investigation
source forensics_env/bin/activate
python3 custom-agent/investigate.py --case /mnt/hostname
```

```bash
# Fast triage — no API key, < 10 seconds
source forensics_env/bin/activate
python3 fast-triage/fast_triage.py /mnt/hostname
```

Requires a Windows disk image mounted read-only on a SANS SIFT Workstation. The venv step is required on SIFT — Debian 12 blocks system-wide pip installs by default.

### Campaign mode — multi-host investigation

```bash
# First host — baseline investigation
python3 custom-agent/investigate.py --case ~/cases/nfury

# Second host — seed with confirmed IOCs from first host
python3 custom-agent/investigate.py --case ~/cases/tdungan nfury

# Third host — all prior confirmed artifacts injected
python3 custom-agent/investigate.py --case ~/cases/nromanoff nfury tdungan
```

Host names resolve to `reports/<host>-iocs.json`. Only Auditor-confirmed artifacts propagate — hallucinations that were refuted on the first host cannot contaminate the next investigation.

---

## The security boundary

Every forensic action flows through one MCP primitive: `run_terminal_command`. Four gates execute in Python before any subprocess call — hard-blocked injection tokens, 53-binary SIFT allowlist, quote-aware pipeline parser, and a write-target guard that enforces `reports/` via `os.path.realpath()`. Evidence modification is structurally impossible, not prompt-dependent.

[Full architecture →](architecture)
