# VERITAS

**LLMs hallucinate forensic findings. Prompt guardrails don't fix it. This does.**

Built for the **SANS FIND EVIL! Hackathon 2026.**

---

## The Problem

Ask an LLM whether credential dumping occurred on a disk image and it will find something that looks like credential dumping — whether or not the binary is actually on disk. The standard response is prompt engineering: *"be skeptical," "only report confirmed findings."* That produces a skeptical-sounding model. It does not produce a verified finding.

These are not the same thing.

This isn't a model quality problem. It's structural. Any system where the same agent that proposes a finding also evaluates it will self-corroborate. You can't fix that with a better prompt.

---

## The Fix

A verification result is only as independent as the information boundary between the investigator and the verifier.

VERITAS enforces that boundary in code. Three agents run in completely isolated MCP sessions with zero shared state:

- **Disk Agent** — investigates event logs, prefetch, registry, network artifacts
- **Memory Agent** — runs Volatility 3 in parallel on the same image
- **Forensic Auditor** — receives the findings list and nothing else. No reasoning chain. No confidence scores. No session context. Must call a real forensic tool and read physical bytes before a finding enters the report.

`CONFIRMED` requires a positive tool return value. Model confidence produces neither `CONFIRMED` nor `REFUTED`.

The critical constraint: **the claim and the verification cannot be on the same layer.** A memory-layer finding flagged by the Memory Agent must be corroborated by disk-layer evidence — not by re-running the same memory tool in a new session. That's the architectural property that makes hallucinations structurally unable to reach the final report.

---

## The Proof

Four hosts, real SANS case data. 32 confirmed, 16 correctly refuted. Under $60 total.

The refutals are the proof the architecture works.

**T1071.001 — active C2 web protocol.** The Memory Agent flagged it: the string `established` appeared in `windows.netscan` output. The Forensic Auditor ran `windows.netscan` independently, read all 432 connection records, found every ESTABLISHED and CLOSE_WAIT connection resolved to Apple, Microsoft, or Google CDN. Returned **REFUTED**.

That is not the model being careful. That is the model running out of connections to check because the actual network data didn't support the claim.

The same four memory-only techniques — T1071.001, T1134, T1547.001, T1574 — were refuted on every host. Same standard, every host, including the attacker's own C2 relay node which was specifically designed to leave nothing on disk.

Every confirmed finding is reproducible: the exact command the Auditor ran, the exact output it returned, the UTC timestamp, the artifact path. A second examiner can mount the same image and reach the same conclusion without touching the AI.

---

## Quick Start

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

Requires a Windows disk image mounted read-only on a SANS SIFT Workstation. The venv step is required on SIFT — Debian 12 blocks system-wide pip installs by default.

```bash
# Campaign mode — confirmed IOCs from nfury seed the tdungan investigation
python3 custom-agent/investigate.py --case ~/cases/tdungan nfury
```

Only Auditor-confirmed artifacts propagate. Hallucinations that were refuted on the first host cannot contaminate the next investigation.

---

## Results

| Host | Role | Confirmed | Refuted | Time | Cost |
|------|------|-----------|---------|------|------|
| nfury (10.3.58.6) | Victim | 15 | 4 | 16 min | $14 |
| tdungan (10.3.58.7) | Victim — campaign mode | 13 | 4 | 15 min | $14 |
| nromanoff (10.3.58.5) | Victim — distinct tool family | 3 | 4 | 15 min | $14 |
| rocba (192.168.1.5) | Attacker's C2 relay node | 1 | 4 | 23 min | $14 |
| **Total** | | **32** | **16** | | **< $60** |

Live investigation reports with full Auditor transcripts: [find-evil.di-sasso.com](https://find-evil.di-sasso.com)

---

MIT License
