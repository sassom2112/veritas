---
title: Project Story
nav_order: 5
permalink: /story
---

# VERITAS — Adversarial Forensic Verification for Windows Incident Response

**SANS FIND EVIL! Hackathon 2026 | Custom MCP Server · Multi-Agent Adversarial Pipeline**

**32 confirmed** across 48 detected, 4 hosts &nbsp;·&nbsp;
**16 correctly refuted** — exactly 4 per host, every host &nbsp;·&nbsp;
**100%** of confirmed findings with physical artifact citation &nbsp;·&nbsp;
**4-gate** MCP security boundary, architecturally enforced &nbsp;·&nbsp;
**~$14** per full disk + memory investigation

---

## Inspiration

A coordinated intrusion compromised the GTG-1002 domain in under ten minutes. The bits recording that fact were frozen the moment the images were acquired. And yet a traditional DFIR team would take days to fully characterize what happened — not because the evidence is missing, but because of a fundamental orchestration bottleneck.

A senior examiner sitting at a SIFT workstation does not lack tools or knowledge. They lack machine-speed synthesis. Manually invoking Volatility, RegRipper, The Sleuth Kit, and YARA, then translating fragmented text output from each into a cohesive timeline, is inherently sequential and inherently slow. When fifty endpoints are hit simultaneously, you cannot scale human analysts to match.

The question we set out to answer: **can we compress Time-to-Understanding from 48 hours to under 30 minutes without sacrificing forensic integrity?**

The speed-only framing misses what actually matters. An autonomous investigator that runs in 8 minutes and hallucinates credential dumping that never happened does not help a responder — it hands them a false incident timeline that will fail the moment a defense attorney or regulator asks to see the supporting artifact. Speed without verifiability is noise at machine velocity. The SIFT community built this platform for practitioners who need findings that survive legal scrutiny. VERITAS is the architecture that makes autonomous investigation forensically defensible, not just fast.

The harder question we did not expect to face: **can we prevent the AI itself from manufacturing the findings we asked it to find?**

LLMs hallucinate because they are trained to be helpful. Ask one whether credential dumping occurred on a disk image and it will find something that looks like credential dumping — whether or not the binary is actually on disk. The standard answer is prompt engineering: tell the model to be skeptical.

An LLM-based security agent also faces a direct adversarial threat: an attacker who can write to logs, craft alert metadata, or control filesystem artifacts can influence what the agent sees and concludes. Prompt-level guardrails are the equivalent of a standard classifier without adversarial hardening — they work until the adversary pushes past the margin. The architectural answer at the model level is adversarial training with separation between clean and adversarial loss. The architectural answer at the system level is the same kind of separation: agents that receive findings but not reasoning, auditors that have a mandate to refute rather than confirm, tool servers that validate before any subprocess executes.

VERITAS is built around a different premise. **A finding is only CONFIRMED when a second independent agent — one instructed to distrust the first — calls a forensic tool and reads the actual bytes off the disk.** If the file is not there, the technique is refuted. No amount of model confidence changes that.

---

## What It Does

VERITAS investigates any mounted Windows forensic image through a four-phase pipeline, fully autonomous from invocation to HTML report.

**Phase 1 — Deterministic triage.** Approximately 25 generic SIFT commands run in under 60 seconds with no LLM involvement. The image is scored against corpus-calibrated signal weights: log-odds ratios computed from 800+ labeled malware samples sourced from MalwareBazaar and HybridAnalysis, covering 9 MITRE ATT&CK techniques. Every command is invariant across investigations — nothing from a previous case contaminates the baseline sweep. The triage net is deliberately wide; the Auditor narrows it.

**Phase 2 — Agentic deep investigation.** A Claude-powered loop with a 75-call tool budget investigates the gaps: event log content, prefetch binary parsing, shellbags, SAM/SECURITY hive extraction, LNK files, hash verification. Critically, the agent receives raw artifacts only — no Pass 1 score, no technique labels. This is an architectural decision, not a prompt instruction. Passing the triage score created measurable confirmation bias: the LLM anchored to what it was told was suspicious rather than reasoning from evidence. The fix was decoupling the two passes entirely.

**Memory analysis — Volatility 3 in parallel.** A separate memory analysis path runs concurrently against the raw memory image, surfacing process injection, VAD anomalies, and runtime artifacts invisible on disk. Techniques confirmed in memory without disk evidence are scored independently and correlated at the auditor stage.

**Phase 3 — Forensic Auditor.** After triage completes, the Auditor challenges every detected technique in parallel (`asyncio.gather`), running up to 5 rounds of 2 independent tool calls per technique. The Auditor receives the findings list only — no access to triage reasoning, no shared session state. Its mandate: *assume every finding is a false positive until the filesystem proves otherwise.* A CONFIRMED verdict requires a positive tool return value. REFUTED requires evidence of absence. Model confidence produces neither.

Confirmed IOCs propagate automatically to subsequent host investigations. The same attacker account, C2 IP, or malware hash found on one host is injected as a priority signal into every subsequent investigation.

---

## How We Built It

**Corpus-calibrated signal weights from real malware, not hand-authored rules.**
Detection signals are weighted using log-odds ratios:

```
log_odds = log2( (p_malware + 0.05) / (p_benign + 0.05) )
weight   = normalize(log_odds) → [0, 1]
```

800+ labeled samples from MalwareBazaar and HybridAnalysis provide the malware frequency estimates. A curated benign baseline of common Windows system strings provides the denominator. Cross-technique tokens are dampened (IDF-equivalent). Signals from confirmed cases retain a floor weight. Every weight is traceable to a source SHA256 — not a model parameter, not an analyst's intuition.

**Adversarial training for Sysmon telemetry — a future detection layer.**
A Red Agent and Blue Agent run 3,000 iterations against 49,519 real Windows Sysmon events from the OTRF Mordor dataset. The Red Agent generates evasion mutations; the Blue Discriminator extracts discriminating field values from every miss and hardens its rules. 2,031 logged evasion attempts. Each exported Sigma rule embeds its per-variant bypass rate.

These rules are validated on live Sysmon telemetry and not yet fully applicable to static disk forensic output — Sysmon event fields like ProcessGuid and CommandLine are absent from dead-disk artifacts. The adversarial training infrastructure is operational; connecting it to a live endpoint telemetry path is the next engineering step.

**Custom MCP Server — hackathon rubric category 2.** VERITAS implements the Custom MCP Server architectural pattern: `sift_server.py` exposes typed forensic functions rather than generic shell access. The agent physically cannot run destructive commands because the server does not expose them. This is architectural enforcement, not prompt-based restriction. The distinction matters: prompt restrictions depend on model compliance; architectural restrictions cannot be bypassed regardless of model behavior.

**One tool, four security layers.**
Every forensic action flows through a single MCP primitive: `run_terminal_command`. Behind it is a four-gate validator enforced in Python before any subprocess call:

1. **22 hard-blocked tokens** — destructive ops (`shred`, `mkfs`, `fdisk`), exfil (`wget`, `curl`, `nc`, `ssh`), privilege escalation (`sudo`, `pkexec`), injection (`$(`, `` ` ``, `${`, `system(`), specific service control verbs
2. **53-binary SIFT allowlist** — unknown binaries rejected unconditionally; `sed` excluded because its `-e` flag passes the pattern space to the shell
3. **Quote-aware pipeline parser** — each pipe segment validated independently; handles `grep -iE '(http|https|ftp)'` without splitting on `|` inside quoted arguments
4. **Write-target guard** — all `>`, `>>`, and `tee` targets resolved with `os.path.realpath` and must land inside `reports/`; symlink traversal and `../` injection fail at the math level

Evidence modification is structurally impossible — not prompt-dependent.

**Append-only audit log.**
Every command is atomically appended via `os.open + os.write` before `subprocess.run` is called. Blocked commands log `blocked_reason`. The audit trail cannot be overwritten through a tool call. A reviewer can open `reports/audit_log.jsonl` and reproduce any finding with one shell command on the same mounted image.

---

## Challenges We Ran Into

**Confirmation bias in the agentic pass.** The original design passed the Pass 1 triage score and technique labels into the Pass 2 system prompt. In practice the LLM anchored to those labels and found supporting evidence for what it was already told was suspicious. The fix required treating Pass 1 and Pass 2 as fully decoupled: Pass 2 receives raw artifact strings and nothing else. The triage score is computed independently after both passes complete.

**The validator blocking legitimate forensic commands.** The first version split on `|` and checked each segment's leading binary. The first time the agent ran `grep -iE '(http|https|ftp)'`, the validator split on the `|` characters inside the single-quoted regex and rejected `https` as an unlisted binary. Fixing this required a quote-aware parser that tracks single-quoted substrings and treats `|` inside them as argument content, not a pipeline separator.

**Over-broad security blocking.** `'service '` was hard-blocked to prevent service management commands. It also blocked every EvtxECmd invocation that queried EventID 7045 (service installs) — which is how PsExec leaves forensic traces. The block was narrowed to specific control verbs (`service start`, `service stop`, `service restart`, `service delete`). In the re-run, T1569.002 was **confirmed**: `psexesvc.exe` found on disk.

**Case sensitivity on Linux NTFS mounts.** Windows XP stores hives at `WINDOWS/system32/config/`. Windows 7 uses `Windows/System32/config/`. On a Linux NTFS mount these are different paths. Every hardcoded path assumption silently fails. The fix was runtime path probing via `os.listdir()` wrapped in helper functions shared across the pipeline.

**Registry hive encoding.** `strings` extracts ASCII. Windows registry hives store content as UTF-16LE. Half of our early false negatives from SOFTWARE and SYSTEM hive queries were caused by this single environment quirk — fixed by switching to `strings -e l`.

**Signal noise from the corpus.** MalwareBazaar and HybridAnalysis metadata contains AV classification labels (`generic`, `trojan`, `bounty`) that appear across virtually every sample. Without filtering, these tokens dominated the corpus and produced high weights for content-free strings. The fix was an AV noise frozenset and a version string regex applied at corpus ingestion time.

---

## Accomplishments

**nfury — full pipeline confirmed a complete APT1 attack chain autonomously. 15 of 19 techniques confirmed.**

Pass 1 (deterministic sweep, no LLM) scored 20 on one technique. Pass 2 (agentic, 75 tool calls) surfaced 13 additional techniques and drove the score to 100. Memory analysis (Volatility 3, parallel) contributed 6 more. Combined triage: 100/100 across 19 detected techniques.

The Auditor challenged all 19 in parallel across 22 argumentation rounds. **15 confirmed. 4 refuted.**

Confirmed attack chain, each finding grounded in a physical artifact citation:

- **T1036 / T1036.005** — `svchost.exe` in `$Recycle.Bin` under vibranium's SID, timestomped to 2008-04-14, no Microsoft PE strings — confirmed httppump backdoor (SHA-256: `f293fdb9...`)
- **T1071** — `http://192.168.1.5/ads/` hardcoded C2 URL in binary; `HttpSendRequestA`, `HttpOpenRequestA`, `WININET.dll` imports confirmed on disk
- **T1003.002** — Volatility `windows.hashdump` extracted Administrator (RID 500), Guest (RID 501), SRL-Helpdesk (RID 1001) hashes from live memory; SAM hive at `Windows/System32/config/SAM` confirmed on disk
- **T1055** — `a.exe` (9KB, PDB: `httppump/inner/i.pdb`) at `vibranium/AppData/Local/Temp/` — `WriteProcessMemory`, `VirtualAlloc`, `CreateThread` imports confirmed; Volatility `malfind` returned 127 `PAGE_EXECUTE_READWRITE` VAD hits across `LogonUI.exe` and `FrameworkServi`
- **T1136 / T1098** — `SRL-Helpdesk` account created 2012-03-13 UTC (Event ID 4720), enabled (4722), modified (4738) — attacker-created service account confirmed in event logs
- **T1078** — `SHIELDBASE\rsydow` network logon from `10.3.58.4` (controller) via Event ID 4624, LogonType 3 — lateral movement credential confirmed
- **T1547** — `System\CurrentControlSet\Services\netman\domain` registry key — httppump persistence mechanism confirmed
- **T1569.002** — `psexesvc.exe` confirmed on disk. **PsExec lateral movement confirmed.** (This was wrongly refuted in the previous run due to the `service ` blocking bug — the fix was validated here.)
- **T1560.001** — `system4.rar`, `chrome.7z` — exfiltration staging archives confirmed on disk
- **T1005, T1105, T1140, T1564** — data collection, tool transfer, deobfuscation (httppump PDB path recovery), Recycle Bin hiding confirmed

Refuted (4) — auditor found no physical corroboration:
- T1071.001 — memory signal `established` only; netscan showed no active HTTP C2 connections
- T1134 — privilege tokens in memory not confirmed as active manipulation
- T1547.001, T1574 — memory-only signals without disk artifact

Total runtime: 16 minutes. Total cost: $14.

**The agentic pass is what found the attack.** A deterministic sweep alone would have returned one technique flag. The 75-call agentic loop surfaced the backdoor, the injection chain, the account manipulation, and the PsExec artifacts. This is the architecture working as designed.

**The auditor is discriminating, not credulous.** 15 confirmed out of 19 — but the 4 refutals matter. T1071.001 was flagged in memory and refuted on disk because the netscan showed no active web C2 connections. The Auditor distinguished between a memory keyword match and a confirmed active C2 channel.

**Every confirmed finding is independently reproducible.** The audit log contains the exact command, the exact output, and the exact timestamp. There are no findings that require trusting the model.

---

**tdungan — second host, campaign mode, cross-host correlation confirmed.**

Run with nfury IOCs injected: `python3 custom-agent/investigate.py --case ~/cases/tdungan nfury`

17 techniques detected. Auditor: **13 confirmed, 4 refuted**. Adjusted score: 100/100. ~15 minutes.

Confirmed attack chain:

- **T1566** — Phishing confirmed as initial access vector. First time this appeared in the campaign — tdungan identifies the entry point.
- **T1003.002** — Volatility `hashdump` extracted Administrator (NT: `8846f7ee...`), SRL-Helpdesk (NT: `4c3f5e9f...`) from live memory. `SRL-Helpdesk` NTLM hash **matches nfury exactly** — attacker-created account credential confirmed across both hosts.
- **T1055** — `svchost.exe` at wrong path (`C:\windows\system32\dllhost\svchost.exe`, spawned from `explorer.exe` not `services.exe`) — injected with 5+ anonymous RWX VadS regions with committed MZ headers (reflective DLL load). Same C2: `http://192.168.1.5/ads/` — **different binary variant** (SHA-256: `91f16fc5...` vs nfury's `f293fdb9...`). Same campaign, evolved tooling.
- **T1003** — `HYDRAKATZ.EXE` in Prefetch — purpose-built credential harvester; name combines Hydra (brute-forcer) and Mimikatz (credential dumper). Custom attacker tooling.
- **T1566 + T1005 + T1074 + T1041** — Phishing → data collection → staging → exfiltration chain confirmed end-to-end.
- **T1021** — Lateral movement via remote services confirmed.
- **T1059, T1071, T1082, T1136, T1140, T1547** — scripting, C2 protocol, discovery, account creation, decode, persistence all confirmed on disk.

Refuted (4): T1134, T1547.001, T1569.002, T1574 — memory-only signals, no disk corroboration. Same pattern as nfury — the Auditor consistently distinguishes memory keywords from physical artifacts.

**IOC propagation worked.** `a.exe` and `SRL-Helpdesk` from the nfury IOC file were recognized as known attacker tools on tdungan. This is the campaign mode doing its job.

---

## What We Learned

**Architectural separation is the only reliable anti-hallucination mechanism.** Prompt instructions telling the model to be skeptical produce a skeptical-sounding model. A second agent with its own MCP session that physically cannot confirm a finding without a positive tool return value produces a verified finding. These are not equivalent.

**Decoupling passes eliminates anchoring bias.** Passing triage results into the investigative pass creates a model that confirms what it was told to look for. Passing only raw artifacts creates a model that reasons from evidence. The difference in output quality was immediately measurable.

**Generic signals and case IOCs are fundamentally different things.** A signal that fires on `psexesvc` in a malware corpus generalizes. A signal that fires on `199.73.28.114` is a case-specific IOC. Baking IOCs into the detection layer inflates scores on familiar images without generalizing to new ones. VERITAS separates these explicitly — corpus weights are generic, IOC files are opt-in at runtime.

**Two validated hosts, consistent auditor behavior.** nfury: 15/19 confirmed, 4 refuted. tdungan: 13/17 confirmed, 4 refuted. Both runs showed the same pattern — memory-only signals refuted, disk-corroborated findings confirmed. The auditor is not case-specific; it applies the same physical verification standard regardless of host.

**The trust gap is prerequisite to the speed gap.** Every competitor in autonomous DFIR races toward faster triage. VERITAS runs in 16 minutes per host — slower than an adversary's 7-minute breakout. But a responder handed a false incident timeline at machine velocity is worse off than one who waits 16 minutes for a verified one. The correct sequence: first, make autonomous findings trustworthy enough to act on without human re-verification. Then compress the timeline. Speed at scale comes from parallelism across hosts, not from reducing per-host time below the point where evidence can be verified. Four simultaneous investigations run in the time of the slowest single host — not their sum.

---

## What's Next

**Novel campaign validation.** Three hosts from one campaign (nfury, tdungan, nromanoff) share an operator, C2 infrastructure, and tooling variants. The architecture generalizes across hosts within the same campaign — including detecting that nromanoff used a distinct tool family (spinlock vs. httppump). The honest next step is running against a second campaign with completely different tooling and measuring false positive rate, missed techniques, and auditor correction rate without any prior IOC seeding.

**Technique coverage expansion.** Corpus weights cover 9 MITRE techniques. The MalwareBazaar and HybridAnalysis APIs can scale this to 50+ with additional corpus collection runs.

**Timeline correlation.** Plaso is on every SIFT workstation. Filtering a supertimeline to the 4-minute window around a confirmed technique execution turns individual artifact matches into activity chains — the difference between "this binary existed on disk" and "this binary ran at 14:32:07, four minutes before this network connection."

**Memory-resident technique coverage.** Techniques that deliberately avoid disk artifacts require memory-first analysis. The Volatility 3 path exists; expanding it to cover process hollowing, DKOM, and kernel rootkit signatures is the next engineering target.

**Neural network detection with an audit admissibility layer.** TrueAllele DNA mixture interpretation and COMPAS recidivism scoring have already been challenged in court on black-box grounds — defendants argued that the inability to inspect model internals violated due process. A deep neural network trained on real Sysmon telemetry would outperform log-odds ratios on detection rate, but its weights cannot be explained in a chain-of-custody review. VERITAS's Forensic Auditor is the direct answer: a black-box detection model can be deployed as the triage layer if, and only if, every flagged finding is subsequently verified by an Auditor that reads physical bytes off disk and produces an artifact citation traceable to a specific tool call. The neural network provides the detection rate. The Auditor provides the admissibility. This is not a workaround — it is the correct architecture for forensic AI that will survive legal challenge.
