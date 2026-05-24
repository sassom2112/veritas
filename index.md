---
title: ADVERSA
nav_order: 1
description: Adversarial forensic verification for Windows incident response
---

# ADVERSA
{: .fs-9 }

Adversarial forensic verification for Windows incident response.
{: .fs-6 .fw-300 }

[Try It Out](submission){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/sassom2112/find-evil-2026){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What ADVERSA does

A Triage Agent finds evidence. A Forensic Auditor challenges every finding independently. Only confirmed physical disk artifacts survive.

```
python3 custom-agent/investigate.py /mnt/hostname
```

| Stat | Value |
|------|-------|
| APT machines investigated | 4 |
| False positives caught by Auditor | 2 |
| Confirmed findings verified on disk | 100% |
| MCP security layers | 4 |
| MITRE techniques covered by corpus weights | 9 |
| Malware samples in corpus | 800+ |
| Auditor challenge rounds per technique | 5 |
| Investigation cost | ~$14 / 17 min |

---

## The core idea

Every LLM-based forensic tool has the same problem: the model *wants* to find evidence. Give it a disk image and ask whether credential dumping occurred, and it will find something that looks like credential dumping — whether or not the binary is actually on disk.

ADVERSA makes hallucinating a confirmed finding **structurally impossible**. A finding is only CONFIRMED when a second independent agent — instructed to distrust the first — calls a forensic tool and reads the actual bytes off disk. If the file is not there, the technique is REFUTED.

---

## Three-phase pipeline

**Phase 1 — Triage Agent**
~25 deterministic SIFT commands, no LLM, scores against corpus-calibrated log-odds weights (9 MITRE techniques, 800+ labeled malware samples).

**Phase 2 — Agentic deep investigation**
75-call Claude loop targeting uncovered domains: event logs, prefetch, SAM hive, WER dumps, network artifacts. Runs blind — no Pass 1 score, no technique labels passed in.

**Phase 3 — Forensic Auditor**
Independent parallel re-verification of every finding. Up to 5 challenge rounds per technique. CONFIRMED requires a physical artifact on disk. Budget exhaustion without positive evidence → INCONCLUSIVE.

---

## Live results (SANS FIND EVIL! 2026 case data)

**nfury** — full pipeline (disk + memory, corpus-calibrated weights, current auditor):

| Phase | Score | Detail |
|------|-------|--------|
| Triage | 100/100 | 9 techniques detected |
| Auditor adjusted | 70/100 | 2 confirmed, 7 refuted |
| Verdict | HIGH | Active compromise confirmed |

Confirmed: **T1003.002** (SAM credential dump), **T1055** (process injection via a.exe loader).
Attack chain: httppump C2 at 199.73.28.114/ads/, attacker account `vibranium`, exfil via system4.rar.

**controller, tdungan** — investigated with an earlier pipeline version (pre-corpus weights). Results in [SUBMISSION.md](submission). Not directly comparable to current system output.
