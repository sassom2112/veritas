---
title: Project Story
nav_order: 4
permalink: /story
---

# ADVERSA — Adversarial Forensic Verification for Windows Incident Response

**SANS FIND EVIL! Hackathon 2026 | Category 7: Persistent Learning Loop**

**4** APT machines confirmed compromised &nbsp;·&nbsp;
**2** triage false positives caught and refuted on physical evidence &nbsp;·&nbsp;
**100%** of confirmed findings verified against disk artifacts &nbsp;·&nbsp;
**4-layer** MCP security boundary &nbsp;·&nbsp;
**11** ASL-trained operational rules deployed

---

## Inspiration

Every LLM-based forensic tool has the same problem: the model *wants* to find evidence. It is helpful by design. Give it a disk image and ask whether credential dumping occurred, and it will find something that looks like credential dumping — whether or not the binary is actually on disk.

The standard answer is prompt engineering: tell the model to be careful, to be skeptical, to only report confirmed findings. Prompt controls are not security controls. They can be overridden, forgotten, or simply ignored when the model is confident.

ADVERSA answers a different question: what if the architecture *itself* made hallucinating a confirmed finding structurally impossible? Not unlikely. Impossible. A finding is only confirmed when a second independent agent — one instructed to distrust the first — calls a forensic tool and reads the actual bytes off the disk. If the file is not there, the technique is refuted. No amount of model confidence changes that.

That is the adversarial dynamic in ADVERSA: not Red vs. Blue in training, but Optimist vs. Cynic in investigation. The Triage Agent proposes. The Forensic Auditor demands proof.

---

## What It Does

ADVERSA investigates any mounted Windows forensic image through a three-phase pipeline, fully autonomous from invocation to HTML report.

**Phase 1 — Deterministic triage.** A Triage Agent dispatches approximately 25 generic SIFT commands in under 60 seconds — no LLM, no case-specific assumptions — and scores the image against 11 ASL-trained rules with MITRE ATT&CK attribution. Every command is invariant across investigations: nothing from a previous case contaminates the baseline sweep.

**Phase 2 — Agentic deep investigation.** A Claude-powered investigation loop with a 75-call tool budget follows up on triage findings. The agent receives an explicit list of what was already checked and a directed list of uncovered investigation domains — event log content, prefetch binary parsing, shellbags, SAM/SECURITY hive extraction, hash verification. It cannot re-run what Pass 1 already covered; every call advances the investigation into new territory.

**Phase 3 — Forensic Auditor.** After the Triage Agent completes, the Forensic Auditor challenges every detected technique in parallel (`asyncio.gather`), running up to three rounds of two tool calls each. The rule is simple: identify the artifact that *must* physically exist on disk if this technique executed, then look for it. Signal string-match alone never confirms a finding. A finding is CONFIRMED only when the definitive artifact is present; REFUTED when the Auditor finds positive evidence of absence.

Multi-host campaigns are supported natively. Confirmed IOCs from one investigation feed the next automatically, and `adversa-merge-iocs.sh` merges findings across hosts into a unified campaign IOC set.

---

## How We Built It

**One tool, four security layers.** Every forensic action flows through a single MCP primitive: `run_terminal_command`. Behind it is a four-layer validator:
1. Hard-blocked dangerous strings (`sudo`, command substitution, `shred`, network tools)
2. A 50-tool SIFT binary allowlist
3. A quote-aware pipeline parser — necessary because standard forensic invocations like `grep -iE '(http|https|ftp)'` contain `|` inside the pattern argument; a naive split would reject `https` as an unlisted binary
4. A redirect guard that verifies all output lands in `reports/` and nowhere else

Evidence modification is structurally impossible, not just unlikely.

**Append-only audit log.** Every tool call is written to the audit log *before* it executes: the command, the agent that called it, a timestamp, and whether the validator passed or blocked it. Chain of custody is a property of the system by construction, not a report we produce afterward.

**Plain-text verifiability.** All Auditor output is plain prose. Every confirmed finding in the HTML report cites the exact tool call that produced it. A reviewer can open `reports/audit_log.jsonl`, find the entry, and reproduce the result with one shell command on the same mounted image.

**Grounded detection rules.** The 11 operational rules were seeded by an adversarial training loop (ASL — Adversarial Signal Learning) on 49,519 real Windows Sysmon events from the OTRF Mordor Security Datasets. A Red Agent evolved evasion variants; a Blue Agent extracted literal field values from missed events. Rules are substrings from real telemetry — no synthetic approximations, no hand-authored patterns. They generalise to real disk images because they were learned from real attack data.

---

## Challenges We Ran Into

The hardest engineering problem was the validator rejecting legitimate forensic commands. The first version used a regex to split on `|` and checked each segment's leading binary against the allowlist. The first time the Triage Agent ran `grep -iE '(http|https|ftp)'`, the validator split it into three segments and rejected `https` as an unlisted binary. Fixing this required a quote-aware parser that tracks single-quoted substrings and correctly identifies `|` inside a quoted argument as part of the argument, not a pipeline separator.

The harder intellectual problem was false positives. Pass 1 triage on the controller host returned a score of 145 with three detected techniques. Two were wrong: masquerading signals triggered by legitimate `svchost.exe` copies in WinSxS, and account discovery signals triggered by a user profile *directory* rather than active enumeration tools. Without the Auditor, an analyst would have received three work items. With the Auditor, they received one — the only technique that left a physical artifact.

---

## Accomplishments That We're Proud Of

Four real APT machines from a single intrusion, investigated autonomously with a consistent pipeline and a complete audit trail.

**nfury:** T1003.001 confirmed with `hydrakatz.exe` found on disk and hash-verified; T1087.001 confirmed via SAM hive analysis. Score 95, no false positives.

**controller:** Triage score 145 reduced to 50 by the Auditor. Two false positives refuted on physical evidence — the exact distinction between "this binary exists in a legitimate Windows location" and "this binary was placed there by an attacker." One technique confirmed: `procdump.exe` in `/Tools/SysInternals/` and `spinlock.exe` in the WER ReportQueue crash dump, confirming the implant executed on this machine.

**tdungan:** Investigated as a blind forward-validation with campaign IOCs from the merged nfury and controller investigations. T1003.001, T1204.002, and T1059 confirmed with physical artifact verification.

The `vibranium` domain account and `spinlock.exe` implant were identified across the enterprise from signals that were extracted from a completely different dataset — Mordor Sysmon telemetry from 2019, not from these images.

---

## What We Learned

Physical artifact verification is not a feature. It is the only thing that separates a forensic finding from a model opinion. Every architecture decision in ADVERSA follows from that single principle.

Architectural guardrails beat prompt controls. The four-layer MCP boundary means no version of the model can write to evidence directories, spawn network connections, or execute arbitrary shell code — not because we told it not to, but because those paths don't exist in the validator. The Forensic Auditor's refutation of false positives works the same way: the model cannot confirm a technique without calling a tool and reading actual output. Confidence is not evidence.

The most valuable component is the one nobody asked for. The Auditor was not in the original design. Adding a second agent whose only job is to disprove the first agent's findings turned a triage tool into an investigation system.

---

## What's Next for ADVERSA

The detection rule foundation needs pool-separation: a signal should only be admitted if it appears in documented attack telemetry and *never* in a real benign baseline. This eliminates the false signal problem at training time rather than relying on the Auditor to catch it at investigation time.

Beyond that: memory forensics integration (Volatility 3 via the MCP layer, for process injection and rootkits invisible on disk), timeline correlation (Plaso super-timeline filtered to confirmed technique time windows), and coverage expansion from 11 to 50+ MITRE techniques via automatic Mordor dataset enumeration.
