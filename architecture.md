---
title: Architecture
nav_order: 4
permalink: /architecture
---

# Architecture

Three agents. Zero shared state. One rule: `CONFIRMED` requires a positive tool return.

---

## The Pipeline

![VERITAS Layered Architecture](docs/adversa-architecture.png)
*Layered security architecture — adversarial training signal through output management.*

```
Mounted Disk Image (read-only)      Raw Memory Image (.001 / .raw)
        |                                     |
        v                                     v
+---------------------------+     +---------------------------+
|    Disk Agent             |     |    Memory Agent           |
|    (blue_agent.py)        |     |    (memory_agent.py)      |
|    Pass 1: ~25 SIFT cmds  |     |    Volatility 3 plugins   |
|    Pass 2: 75-call loop   |     |    Pass 2: agentic loop   |
|    corpus-calibrated       |     |    VAD / injection / creds|
+---------------------------+     +---------------------------+
        |                                     |
        |  findings list only (technique IDs, nothing else)
        +------------------------------+------+
                                       v
                        +---------------------------+
                        |    Forensic Auditor       |  isolated MCP session
                        |    (auditor_agent.py)     |  no shared state
                        |                           |  mandate: assume false
                        |                           |  5 rounds × 2 tool calls
                        +---------------------------+
                                       |
                                       v
                          CONFIRMED / REFUTED / INCONCLUSIVE
                          + append-only audit log (audit_log.jsonl)
                          + HTML report
```

**The structural guarantee:** The Auditor receives technique IDs and nothing else from the Disk and Memory Agent sessions. `CONFIRMED` requires a positive tool return value. Timeout returns `INCONCLUSIVE` — never `CONFIRMED`.

---

## Architectural Pattern

**Custom MCP Server + Multi-Agent Framework**

A purpose-built MCP server exposes typed forensic functions rather than a generic shell. Three Claude agents run in completely separate MCP sessions with zero shared state. The Disk Agent and Memory Agent investigate on disjoint evidentiary layers. The Forensic Auditor independently re-runs tool calls to verify every finding. A `CONFIRMED` verdict requires a positive tool return — not model confidence. The agents physically cannot run destructive commands because the MCP server does not expose them.

---

## Security Boundaries

| Boundary | Type | Enforcement |
|----------|------|-------------|
| Operator instructions / system prompts | Prompt-based | Model can ignore |
| MCP Validator Gate (4 gates) | **Architectural** | Python-enforced before any `subprocess.run()` |
| Binary allowlist | **Architectural** | 53 approved SIFT tools — unknown binaries rejected |
| Redirect guard | **Architectural** | `os.path.realpath()` — no writes outside `reports/` |
| Auditor independence | **Architectural** | Separate MCP session, separate asyncio task, no shared state |

---

## The MCP Validator Gate

Every forensic action flows through one primitive: `run_terminal_command`. Four gates execute in Python before any subprocess call:

**Gate 1 — Argument injection prevention**
22 hard-blocked tokens: destructive ops (`shred`, `mkfs`), exfil tools (`curl`, `wget`, `nc`), privilege escalation (`sudo`), and command substitution (`` $() ``, backtick). An approved binary can still be weaponized if attacker-controlled log content injects shell metacharacters into its arguments.

**Gate 2 — Deny-all binary enforcement**
53-binary SIFT allowlist. Every binary not on the list is rejected unconditionally. `sed` is excluded — its `-e` flag passes the pattern space to the shell.

**Gate 3 — Quote-aware pipeline parser**
Each pipe segment validated after tracking single-quoted substrings. `grep -iE '(http|https|ftp)'` passes correctly — `|` inside quotes is argument content, not a separator.

**Gate 4 — Write-target guard**
All `>`, `>>`, `tee` targets resolved via `os.path.realpath()`. Must resolve inside `reports/`. Symlink and `../` attacks fail at the path arithmetic level.

Every command is atomically appended to `audit_log.jsonl` via `os.open + os.write` **before** `subprocess.run` is called. Evidence modification is structurally impossible.

---

## Auditor Independence

The Forensic Auditor receives:
- A JSON list of technique IDs

The Forensic Auditor does **not** receive:
- The Disk Agent's or Memory Agent's tool call history
- Either agent's reasoning or analysis
- Confidence scores or weights
- Any context from either investigation session

This is enforced by the code, not a prompt. Reading `auditor_agent.py` verifies the property.

---

## Campaign IOC Propagation

After a host is investigated, confirmed artifacts are extracted to a structured JSON file. Only Auditor-confirmed artifacts — nothing the Auditor rejected.

```bash
# Investigate second host with first host's confirmed IOCs injected
python3 custom-agent/investigate.py --case ~/cases/tdungan nfury
```

The IOC file injects into the deterministic sweep of the next host — no LLM, no API call. Hallucinations from the first host cannot contaminate the second investigation because they never made it into the IOC file.

---

## Detection Layer — Proof of Concept

The triage layer generates candidates for the Auditor. It is not the architectural contribution.

| Component | What it does | Status |
|-----------|-------------|--------|
| `blue_agent.py` Pass 1 | ~25 SIFT commands, corpus-calibrated weights, <60s | Working |
| `blue_agent.py` Pass 2 | 75-call Claude loop, raw artifacts only, no labels | Working |
| `memory_agent.py` | Volatility 3 parallel path — process injection, VAD, creds | Working |
| Corpus weights | Log-odds from 800+ MalwareBazaar/HybridAnalysis samples | POC, 9 MITRE techniques |

The roadmap replaces corpus weights with a neural network trained against a validated benign baseline. The Auditor architecture is unchanged — any detection signal feeds the same verification layer.
