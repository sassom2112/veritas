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
| APT hosts investigated (current pipeline) | 2 |
| Techniques confirmed across both hosts | 28 of 36 detected |
| Techniques refuted by Auditor | 8 |
| Confirmed findings with physical artifact citation | 100% |
| MCP security layers | 4 |
| MITRE techniques covered by corpus weights | 9 |
| Malware samples in corpus | 800+ |
| Investigation cost | ~$14 / ~15 min per host |

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

---

**tdungan** — full pipeline with nfury IOCs injected (campaign mode):

| Phase | Score | Detail |
|------|-------|--------|
| Triage (disk + memory) | 100/100 | 17 techniques detected |
| Auditor adjusted | 100/100 | 13 confirmed, 4 refuted |
| Verdict | HIGH | Active compromise confirmed |

Confirmed (13): T1003.002, T1005, T1021, T1041, T1055, T1059, T1071, T1074, T1082, T1136, T1140, T1547, **T1566** (Phishing — initial access).
Refuted (4): T1134, T1547.001, T1569.002, T1574 — memory signals without disk corroboration.

Key artifacts: `svchost.exe` masquerade at wrong path (`dllhost\svchost.exe`, spawned from `explorer.exe`), same C2 `192.168.1.5/ads/` — different binary variant (SHA-256: `91f16fc5...`). `HYDRAKATZ.EXE` in Prefetch — purpose-built credential harvester (Hydra + Mimikatz). `PKXEZY1TJI98.EXE` dropper. `SRL-Helpdesk` NTLM hash `4c3f5e9f...` — **matches nfury**, confirming credential reuse across hosts.

**Cross-host campaign correlation:** Same C2 infrastructure, same `SRL-Helpdesk` account hash, `a.exe` IOC from nfury present on tdungan. T1566 on tdungan identifies phishing as the initial access vector for the campaign.

Additional hosts (controller, nromanoff) pending re-run with current pipeline.
