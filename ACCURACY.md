---
title: Accuracy & Evidence Integrity
nav_order: 10
permalink: /accuracy
---

# Accuracy & Evidence Integrity

The primary accuracy claim in VERITAS is not a detection rate. It is a verification
guarantee: **every CONFIRMED finding is backed by a positive return value from a real
forensic tool call.** The numbers below are evidence for that claim.

---

## Forensic Auditor Results — 4 Hosts

| Host | Candidates | Confirmed | Refuted | Inconclusive |
|------|-----------|-----------|---------|--------------|
| nfury (10.3.58.6) | 19 | 15 | 4 | 0 |
| tdungan (10.3.58.7) | 17 | 13 | 4 | 0 |
| nromanoff (10.3.58.5) | 7 | 3 | 4 | 0 |
| rocba (192.168.1.5) | 5 | 1 | 4 | 0 |
| **Total** | **48** | **32** | **16** | **0** |

**100% of confirmed findings** have a physical artifact citation traceable to a specific
tool call in the append-only audit log. Every confirmed technique can be independently
reproduced with one shell command on the same mounted image.

**Exactly 4 refutals per host** across all four investigations — three victim machines and
a C2 relay node, two different tool families. The Auditor applies the same verification
standard regardless of host type.

---

## The Refutals Are the Evidence

The 16 refuted findings are not failures. They are the architecture working.

The same four techniques were refuted on every host: T1071.001, T1134, T1547.001, T1574.
All four are memory-resident signals with no disk corroboration. The Auditor consistently
distinguishes between a memory keyword match and a confirmed physical artifact.

**T1071.001 on nfury — the clearest case:**
Memory triage flagged active C2 web protocol from the string `established` in netscan
output. The Auditor ran `windows.netscan` and checked all 432 connection records. Every
ESTABLISHED and CLOSE\_WAIT connection resolved to Apple, Microsoft, or Google CDN
infrastructure. Returned REFUTED: no active HTTP/HTTPS C2 connections found.

**T1547.001 on nfury — exhaustive checking:**
Memory triage flagged registry Run key persistence. The Auditor checked the SOFTWARE hive,
SAM, SECURITY, BCD, Syscache, and 11 NTUSER.DAT files across all user profiles over three
challenge rounds. The only Run key entries: Windows Sidebar entries dated 2009-07-14 —
the stock Windows 7 installation timestamp. Returned REFUTED: signal fired on the key path
in memory, not on a malicious value in the key.

**T1055 on rocba — fail-safe under resource pressure:**
Round 1: `windows.malfind` timed out after 120 seconds. Returned INCONCLUSIVE — not
CONFIRMED. Round 2: recovered one VAD record before timeout. `MsMpEng.exe` with two
`PAGE_EXECUTE_READWRITE` VadS regions and x64 shellcode prologue. Returned CONFIRMED.
Timeout produces INCONCLUSIVE, not a hallucinated finding.

---

## Triage Layer Honest Assessment

The corpus-calibrated detection layer is a **proof of concept**.

| Metric | Value | Context |
|--------|-------|---------|
| Pass 1 contribution to candidates | 2 of 48 | Corpus weights, deterministic sweep |
| Pass 2 contribution to candidates | 46 of 48 | Agentic investigation |
| Techniques confirmed by Auditor | 32 of 48 (67%) | Auditor is the precision layer |
| Techniques refuted by Auditor | 16 of 48 (33%) | Correct — memory signals without disk evidence |
| MITRE techniques in corpus weights | 9 | MalwareBazaar + HybridAnalysis signals |
| FP rate on benign endpoints | High | Designed for known-suspicious images, not live monitoring |

The triage layer is deliberately wide. The Auditor provides the precision.

---

## Sysmon Adversarial Training — Honest Scope

The adversarial Red/Blue training loop (`brain.py`) operates on Sysmon live telemetry.
Sysmon event fields (`ProcessGuid`, `CommandLine`, `ParentImage`) are absent from static
disk forensic output. These signals do not independently drive disk-forensic detections
in the current pipeline. The deployment path for this component is a live Sysmon endpoint.

Technical details are documented in [Domain Gap Analysis](/docs/domain_gap_results).

---

## Evidence Integrity

Every confirmed finding is reproducible without the AI:

1. Open `reports/audit_log.jsonl`
2. Find the Auditor tool call for the confirmed technique
3. Run the exact command on the same mounted image
4. The output matches

The audit log is append-only — written via `os.open + os.write` before each
`subprocess.run` call. It cannot be overwritten through a tool call. Blocked commands
log their `blocked_reason`. The chain of custody is complete from invocation to verdict.
