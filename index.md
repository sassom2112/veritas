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
| Techniques confirmed on nfury (current pipeline) | 15 of 19 detected |
| Techniques refuted by Auditor | 4 |
| Confirmed findings with physical artifact citation | 100% |
| MCP security layers | 4 |
| MITRE techniques covered by corpus weights | 9 |
| Malware samples in corpus | 800+ |
| Auditor challenge rounds per technique | up to 5 |
| Investigation cost | ~$14 / 16 min |

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
| Triage Pass 1 (deterministic) | 20/100 | 1 technique — T1560.001 only |
| Triage Pass 2 (agentic, 75 calls) | 100/100 | 14 additional techniques surfaced |
| Memory (Volatility 3, parallel) | 100/100 | 6 memory-resident techniques |
| Auditor adjusted | 100/100 | 15 confirmed, 4 refuted |
| Verdict | HIGH | Active compromise confirmed |

Confirmed (15): T1003.002, T1005, T1036, T1036.005, T1055, T1071, T1078, T1098, T1105, T1136, T1140, T1547, T1560.001, T1564, **T1569.002** (PsExec).
Refuted (4): T1071.001, T1134, T1547.001, T1574 — memory signals without disk corroboration.

Key artifacts: httppump backdoor (`svchost.exe` in `$Recycle.Bin`, timestomped to 2008-04-14, C2 at `192.168.1.5/ads/`), `a.exe` injector (127 `PAGE_EXECUTE_READWRITE` VADs via Volatility malfind), `SRL-Helpdesk` account creation (Event ID 4720), `psexesvc.exe` on disk, `system4.rar` + `chrome.7z` exfil staging.
Attacker account: `vibranium` (SID S-1-5-21-2036804247-3058324640-2116585241-1673).

Additional hosts (controller, tdungan, nromanoff) pending re-run with current pipeline.
