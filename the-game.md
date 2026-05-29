---
title: How It Works
nav_order: 2
permalink: /how-it-works
---

# How VERITAS Works
{: .fs-9 }

Explained as a two-player game.
{: .fs-6 .fw-300 }

---

## The Setup

A Windows machine got compromised. You don't know what happened. You have a disk image and a memory dump. Your job is to figure out what the attacker did.

The problem: AI investigators hallucinate. Ask an LLM what happened and it will find something that looks like credential dumping whether or not the binary is actually on disk. High confidence. Wrong answer. You can't tell the difference.

That's not a model quality problem. It's a structural property of any system where the same agent that proposes a finding also evaluates it.

---

## The Two Players

**The Optimist — Triage Agent**

Goes through everything. Event logs, prefetch files, registry hives, memory dumps, network artifacts. Forms hypotheses. Builds a findings list. Fast, thorough, creative.

Also wrong sometimes. Doesn't know it's wrong.

**The Cynic — Forensic Auditor**

Receives only the findings list. Never sees the Optimist's reasoning. Never sees the evidence chain. Never sees how confident it sounded. Just the claims — a list of technique IDs and nothing else.

Has five rounds, two tool calls per round. Must call real forensic tools and read physical bytes off disk or out of memory. Returns one of three verdicts per finding:

- **CONFIRMED** — positive tool return value. The artifact is there.
- **REFUTED** — evidence of absence. The artifact is not where the technique requires it.
- **INCONCLUSIVE** — budget exhausted, evidence insufficient for either verdict.

No other input is valid. Model confidence counts for nothing.

---

## The Rules

The Optimist can say anything.

The Cynic can only say what the filesystem proves.

A finding is only CONFIRMED when the Cynic calls a real forensic tool and reads physical bytes. The Cynic cannot ask the Optimist for clarification. Cannot see its reasoning chain. Cannot be influenced by how confident it sounded. This is structural isolation — a session boundary enforced in code, not a prompt instruction.

**The MCP Validator Gate** enforces this at the subprocess level. Before any tool call executes, four gates run in Python:

1. 22 hard-blocked tokens — no destructive ops, no exfil tools, no command injection
2. 53-binary SIFT allowlist — unknown binaries rejected unconditionally
3. Quote-aware pipeline parser — handles real forensic regex without false blocking
4. Write-target guard — all output must land in `reports/`, resolved via `os.path.realpath()`

Evidence modification is structurally impossible — not prompt-dependent.

---

## The Scoreboard

Four hosts. Same Auditor. Same rules.

| Host | Role | Investigated | Confirmed | Refuted |
|------|------|-------------|-----------|---------|
| nfury (10.3.58.6) | Victim | 19 | **15** | 4 |
| tdungan (10.3.58.7) | Victim (campaign) | 17 | **13** | 4 |
| nromanoff (10.3.58.5) | Victim | 7 | **3** | 4 |
| rocba (192.168.1.5) | C2 relay node | 5 | **1** | 4 |
| **Total** | | **48** | **32** | **16** |

The refuted count happens to be 4 on each host. The refuted *techniques* are not the same.

| Host | Refuted techniques |
|------|--------------------|
| nfury | T1071.001, T1134, T1547.001, T1574 |
| tdungan | T1134, T1547.001, **T1569.002**, T1574 |
| nromanoff | memory-only signals, no disk corroboration |
| rocba | T1071.001, T1134, T1547.001, T1574 |

Notice T1569.002 — PsExec lateral movement. On nfury, the Auditor found `psexesvc.exe` on disk and returned **CONFIRMED**. On tdungan, the Auditor checked and found no binary — returned **REFUTED**. Same technique. Two different hosts. Two different verdicts. The Auditor is making case-specific decisions based on what's actually on each disk, not running a fixed pattern.

The consistent pattern isn't the number — it's the class of signal. Memory analysis against Windows 7 images tends to surface the same noise techniques (access token manipulation, hijack execution flow, run key persistence, active C2 connections) because these patterns appear in any live Windows memory image. The Auditor correctly dismisses them every time they lack disk corroboration.

**The refutals are the proof the game works.**

On nfury, T1071.001 was flagged because the string `established` appeared in `windows.netscan` output. TCP state strings appear in memory regardless of whether any malicious connection is active. The Auditor ran `windows.netscan` and checked all 432 connection records. Every ESTABLISHED and CLOSE\_WAIT connection resolved to Apple, Microsoft, or Google CDN infrastructure. Returned REFUTED.

That is not the Cynic being careful. That is the Cynic running out of connections to check because the actual network data didn't support the claim.

Without the Cynic you ship 19 findings on nfury. Four of them are wrong. You don't know which four.

---

## The Special Case — rocba

rocba is the C2 relay node. Zero disk artifacts by design — no persistence, no lateral movement, no staged files. The attacker didn't leave anything on disk.

The Auditor found one thing: T1055 in `MsMpEng.exe` — Windows Defender's own engine. Two anonymous `PAGE_EXECUTE_READWRITE` memory regions with an x64 shellcode dispatch trampoline. The attacker injected into their own AV to hide C2 traffic inside a trusted process.

In Round 1, `windows.malfind` timed out. The Auditor returned INCONCLUSIVE — not CONFIRMED. Timeout does not produce a confirmed finding. The game fails safe.

In Round 2, it recovered one VAD record before the timeout and returned CONFIRMED.

The architecture works on hosts that are specifically designed to defeat forensic analysis.

---

## Campaign Mode — The Meta-Game

After nfury is solved, confirmed IOCs go into a file. SHA-256 hashes. C2 addresses. Account names. Only confirmed artifacts — nothing the Cynic rejected.

When tdungan is investigated, the Triage Agent loads that file and hunts specifically for those artifacts. Not general search. Directed investigation seeded by physically verified prior findings.

Same httppump variant. Same C2 at `192.168.1.5/ads/`. Same `SRL-Helpdesk` account. Different host. The NTLM hash matched exactly — `4c3f5e9f...` on both machines. Credential reuse confirmed by artifact, not by model inference about campaign patterns.

**The campaign propagates only what was proven. Hallucinations don't survive the first host. They cannot infect the next investigation.**

The IOC file contains no LLM reasoning, no confidence scores, no context from the prior session. Just verified artifact values. The downstream agent gets evidence, not a story.

---

## What the Architecture Actually Does

The Optimist is unconstrained. Given a suspicious disk image and a mandate to find compromise, it will find something that looks like every technique on the ATT&CK matrix. Some findings will be real. Some will be memory noise. Some will be parser artifacts. It cannot tell the difference.

The Cynic is the constraint layer. It forces every finding back into physical reality before it enters the report.

| | Findings shipped | Wrong findings | Cited to physical artifact |
|---|---|---|---|
| Without Cynic | 19 | 4 (unknown) | 0 |
| With Cynic | 15 | 0 | 15 |

The architecture doesn't make the Optimist smarter. It makes the Optimist's hallucinations structurally irrelevant to the final output.

---

## How to Run the Game

```bash
# Fast triage — no API key, < 10 seconds, decides if the image is worth $14
python3 fast-triage/fast_triage.py /mnt/hostname

# Full game — Optimist investigates, Cynic verifies, HTML report written
python3 custom-agent/sift_server.py          # Terminal 1
python3 custom-agent/investigate.py /mnt/hostname  # Terminal 2

# Campaign mode — seed with confirmed IOCs from prior hosts
python3 custom-agent/investigate.py --case ~/cases/tdungan nfury
```

Every confirmed finding in the output traces to a specific tool call in an append-only audit log. A second examiner can reproduce any finding with one shell command on the same mounted image. No trust required.

[View Live Investigation Reports](submission){: .btn .btn-primary .mt-4 }
[Read the Architecture](architecture){: .btn .mt-4 }
