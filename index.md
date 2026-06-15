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

A Triage Agent investigates. A Forensic Auditor challenges every finding independently. CONFIRMED requires a positive return value from a real forensic tool. Model confidence counts for nothing.

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
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."

# Full investigation — auto-discovers disk mount + memory image
python3 custom-agent/investigate.py --case /cases/hostname

# Explicit paths (disk must be pre-mounted via ewfmount)
python3 custom-agent/investigate.py /mnt/hostname --memory /cases/hostname/mem.001
```

Requires a Windows disk image mounted read-only on a SANS SIFT Workstation.

---

## The security boundary

Every forensic action flows through one MCP primitive: `run_terminal_command`. Four gates execute in Python before any subprocess call — hard-blocked injection tokens, 53-binary SIFT allowlist, quote-aware pipeline parser, and a write-target guard that enforces `reports/` via `os.path.realpath()`. Evidence modification is structurally impossible, not prompt-dependent.

[Full architecture →](architecture)
