# ADVERSA — Adversarial Forensic Investigation Framework

**A dual-agent AI that autonomously investigates Windows disk images for evidence of compromise.
A Triage Agent hunts for artifacts. A Forensic Auditor independently challenges every finding.
Only what survives physical verification makes it into the report.**

Built for the **SANS FIND EVIL! Hackathon 2026** — a competitive digital forensics challenge where
participants investigate real Windows disk images to identify attacker techniques, lateral movement,
and persistence across a multi-host environment.

---

## Why Two Agents?

LLMs hallucinate. In forensics, a hallucinated finding is a false accusation.

ADVERSA enforces a rule borrowed from adversarial ML: **the model that finds evidence and the model
that verifies it must be independent**. The Forensic Auditor has no access to the Triage Agent's
reasoning — it re-runs its own tool calls from scratch and demands to see bytes on disk.
On the live case data, this caught 2 false positives the triage pass scored as HIGH confidence.

Detection rules are trained the same way: a **Red Agent** generates evasion variants of known
attack patterns, a **Blue Agent** learns to catch them. Over 4,500+ iterations on ~49,500 real
Windows Sysmon events, the system autonomously recovered from a domain gap — zero human
intervention required. **Per-event detection rate is the wrong metric for a post-compromise
forensic tool**: the relevant result is that the system correctly identified attacker techniques
on all 3 SANS case hosts, with the Auditor catching and removing 2 false positives.

---

## What It Does

![ADVERSA Layered Forensic Architecture Stack](docs/adversa-architecture.png)

Detection is backed by **11 operational rules** trained via an adversarial Red vs Blue loop on
**~49,519 real Mordor/OTRF Sysmon events** across 9 MITRE ATT&CK techniques (72 generalizable
`asl_trained` signals + 23 case-specific `forensic_ioc` signals).

---

## Quick Start

### Prerequisites

```bash
# Ubuntu / SANS SIFT Workstation (recommended)
git clone https://github.com/sassom2112/adversa.git
cd adversa
python3 -m venv ~/adversa-env
source ~/adversa-env/bin/activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY="sk-ant-..."
```

The framework requires access to a **mounted Windows disk image** at a path like `/mnt/hostname`.
It reads the filesystem using standard SIFT/Sleuth Kit tools — no write access to evidence is needed.

### Run a full investigation

```bash
# Terminal 1 — start the forensic MCP tool server
python3 custom-agent/sift_server.py

# Terminal 2 — run the adversarial pipeline
python3 custom-agent/investigate.py /mnt/tdungan
```

What you will see:
- **Pass 1** — deterministic IOC sweep (~5 s), scored immediately
- **Pass 2** — 75-call Claude agentic loop, deep technique-specific scans
- **Forensic Auditor** — independent re-verification of every finding
- HTML report written to `reports/<hostname>-report.html`
- IOCs auto-propagated to the next `investigate.py` run (campaign mode)

### Investigate multiple hosts (campaign mode)

```bash
python3 custom-agent/investigate.py /mnt/nromanoff
# → writes reports/nromanoff-iocs.json

python3 custom-agent/investigate.py /mnt/nfury
# → auto-loads reports/nromanoff-iocs.json

python3 custom-agent/investigate.py /mnt/controller
# → auto-loads reports/nromanoff-iocs.json + reports/nfury-iocs.json
```

Each run writes a `reports/<hostname>-iocs.json` file. On every subsequent run,
`investigate.py` scans `reports/` for all IOC files from other hosts and merges
them automatically — no flags required.

### Fast triage only (no API key, < 10 seconds)

```bash
python3 fast-triage/fast_triage.py /mnt/hostname
# Deterministic IOC sweep, prints confidence score and matched signals
# Auto-escalates to full pipeline if score ≥ 30
```

---

## Components

| File | Purpose |
|------|---------|
| `custom-agent/investigate.py` | **Main entry point** — orchestrates full pipeline |
| `custom-agent/blue_agent.py` | Triage Agent — two-pass SIFT + Claude agentic investigator |
| `custom-agent/auditor_agent.py` | Forensic Auditor — adversarial re-verification loop |
| `custom-agent/sift_server.py` | MCP tool server — 4-layer security, forensic tool access |
| `custom-agent/html_report.py` | HTML report generator (exec summary, IOC table, transcripts) |
| `custom-agent/extract_iocs.py` | IOC extractor — C2 IPs, file hashes, accounts from findings |
| `custom-agent/brain.py` | ASL training loop — Red vs Blue adversarial signal learning |
| `custom-agent/mordor_agent.py` | Red Agent — draws real Mordor Sysmon events, generates evasions |
| `custom-agent/export_patterns.py` | Exports trained patterns → `operational_rules.json` + Sigma rules |
| `custom-agent/pattern_db.py` | SQLite pattern store — versioned signals with hit/miss counters |
| `fast-triage/fast_triage.py` | Deterministic triage — no LLM, sub-10 s |
| `adversa.sh` | One-command launcher with API key prompt |

---

## Pre-trained Rules

`reports/operational_rules.json` ships with **11 operational rules** covering:

| Technique | Coverage |
|-----------|----------|
| T1003.001 | LSASS memory dump (mimikatz, spinlock, sekurlsa) |
| T1071.001 | C2 web protocol (IP-based beaconing, /ads/ URI pattern) |
| T1569.002 | Service execution (PsExec, PSEXESVC, sc.exe create) |
| T1547.001 | Registry run key persistence (dllhost\\svchost) |
| T1087.001 | Local account enumeration |
| T1204.002 | User execution of malicious file |
| T1036.005 | Masquerading via renamed system binaries |
| + 4 more  | Credential access, lateral movement, exfiltration |

`reports/sigma_rules/` contains adversarially-validated Sigma rules exportable to any SIEM.

### Retrain from scratch (~30 min)

```bash
# Download Mordor datasets first (see DATASET.md)
python3 custom-agent/brain.py            # adversarial training (default cap: 1,500 iterations)
python3 custom-agent/export_patterns.py  # → operational_rules.json + sigma_rules/
```

---

## Results

### Live Investigation — SANS FIND EVIL! 2026 Case Data

| Host | Confirmed Techniques | Score | Verdict |
|------|---------------------|-------|---------|
| tdungan | T1003.001, T1204.002, T1059 | 100/100 | HIGH |
| nfury | T1003.001, T1087.001 | 95/100 | HIGH |
| controller | T1003.001 | 50/100 | HIGH (2 FPs caught by Auditor) |

The controller result is the most illustrative: the Triage Agent scored 145, flagging three
techniques. The Forensic Auditor refuted two (legitimate svchost in WinSxS, user profile
directory traversal). Final confirmed score: 50. One real finding, zero false accusations.

See [ACCURACY.md](ACCURACY.md) for full iteration progression. See [SUBMISSION.md](SUBMISSION.md)
for the full case walkthrough with terminal output.

---

### Adversarial Training — Domain Gap Discovery and Autonomous Recovery

The system started with near-zero detection on real Sysmon telemetry — no domain knowledge,
no human-labeled examples. Training exposed a measurable domain gap between formatted artifact
strings and raw Sysmon field structure; the Red vs Blue loop navigated it without human
intervention.

![Training progression](reports/training_graphs.png)

**What the metrics actually mean**

The correct evaluation unit for a forensic investigation tool is not per-event detection rate —
it is whether the investigation correctly characterizes a compromised host. ADVERSA investigates
hosts, not individual events. A single forensic artefact (a GrantedAccess mask, a PsExec service
DLL, a device path format) surfaced in any of 75 tool calls is sufficient to confirm a technique.
Per-event recall will always appear low on imbalanced telemetry; investigation-level accuracy is
the number that matters.

| Metric | Value | Context |
|--------|-------|---------|
| Training iterations | 4,500+ | Logged in `accuracy_report.json`; `brain_state.json` records 7,158+ |
| `asl_trained` signals in production rules | 72 | Generalizable; tested on independent dataset |
| `forensic_ioc` signals in production rules | 23 | Case-specific IOCs, excluded from cross-dataset testing |
| Red evasion variants evolved | 2,375+ | Logged in `brain_state.json` |
| MITRE techniques covered | 9 | Via adversarial training; 11 total rules including IOC-only |
| In-training detection rate | 27% recall, 82% precision, F1 0.40 | `accuracy_report.json` |
| Holdout detection rate (last 20% per technique) | 5.6% recall, 99.8% precision, F1 0.10 | `ablation_study.json` |
| **Investigation-level accuracy (3 SANS hosts)** | **3/3 hosts correctly characterized** | Live case; 2 FPs caught by Auditor |

The holdout recall is low by design: the test set holds out the tail of each technique's JSONL
file, which skews toward later, more varied Sysmon events that the earliest training signals don't
generalize to. The precision (99.8%) shows the signals that do fire are not noise. The
investigation result — 3/3 hosts, 2 false accusations removed — is the correct metric for the
problem being solved.

**What training actually produced**

The two signals most diagnostic of ADVERSA's training contribution:

- `0x1fffff` — the `GrantedAccess` bitmask that fires on LSASS credential dumping regardless of
  tool name. Human-authored rules block mimikatz by name. This rule catches any process requesting
  full LSASS access.
- `psmserviceexthost.dll` — a PsExec service DLL path surfaced from raw Mordor telemetry.
  Normalizing rules strip paths; this signal fires on the device path format itself.

Both are `asl_trained`, both verified against an independent EVTX-ATTACK-SAMPLES dataset never
seen during training (see Cross-Dataset Validation below).

---

## Security Architecture

![ADVERSA Guardrails — Anti-Hallucination Trust Chain & MCP Security Boundary](docs/adversa-guardrails.png)

The design principle throughout: **make bad actions structurally impossible, not prompt-dependent.**

---

### What the agent can and cannot do

The MCP server exposes `run_terminal_command` — a single typed entry point that accepts a command
string. Claude constructs commands exactly as a forensic analyst would at the terminal. This is a
deliberate design choice: pre-packaged tool wrappers would limit the agent to a fixed set of
forensic patterns; exposing the full SIFT toolkit with a validator gives the same expressiveness
while enforcing the boundary at execution time.

Every command goes through `_validate_command()` before `subprocess.run` is ever called.

---

### Layer 1 — Hard-blocked substrings

Raw string match on the lowercased command before any parsing:

| Category | Blocked tokens |
|----------|---------------|
| Destructive | `shred`, `mkfs`, `fdisk`, `parted`, `wipefs`, `dd if=/dev/zero`, `dd if=/dev/urandom` |
| Exfiltration | `wget`, `curl `, `nc `, `ncat `, `netcat `, `ssh `, `scp `, `rsync ` |
| Privilege escalation | `sudo `, `su `, `pkexec` |
| Process manipulation | `kill `, `killall`, `systemctl`, `service ` |
| Substitution injection | `$(`, `` ` `` |
| Variable expansion | `${` — blocks `echo ${ANTHROPIC_API_KEY}` and similar env reads |
| In-process shell execution | `system(` — blocks `awk 'BEGIN{system("cmd")}'` and equivalents |

Runs before the shell sees the command. Cannot be bypassed by encoding because the match is
on the raw string, not the interpreted result.

---

### Layer 2 — Forensic binary allowlist + per-binary argument guards

Each pipe segment is split with `shlex.split` (handles quoted escapes). The leading binary must
be in an explicit `frozenset` of approved SIFT tools. Blocked by omission — anything absent from
the list is rejected without needing a pattern match.

`sed` is intentionally excluded: GNU `sed`'s `e` flag passes the pattern space directly to the
shell for execution, bypassing all pipeline validation. `awk` and `grep` cover the same forensic
text-processing use cases.

Per-binary argument guards run after the allowlist check:

**`python3` / `python`** — `-c` flag blocked even though the binary itself is allowed. Closes
inline code execution without removing `python3` from the allowlist (needed for Volatility).

**`find`** — `-exec` and `-execdir` targets extracted and validated against the allowlist.
`find -exec sh -c` is blocked; `find -exec sha256sum {} \;` is allowed.

**`xargs`** — the command argument (first non-flag token) is extracted and validated against
the allowlist. `xargs sh -c` is blocked; `xargs md5sum` is allowed.

**`tee`** — all output file arguments are validated through the same write-target check as
shell redirects (see Layer 3). `tee` writes files as a program side-effect without using `>`
syntax, so it is validated separately.

---

### Layer 3 — Write-target guard

All write targets — shell `>` / `>>` redirects and `tee` file arguments — are resolved with
`os.path.realpath(os.path.join(os.getcwd(), raw))` and must land inside `reports/`. This uses
`cwd` rather than a fixed base path so the check matches what the shell will actually do.

`/dev/null` is additionally whitelisted.

`audit_log.jsonl` is explicitly denied regardless of path — even a correctly-resolved path
inside `reports/` cannot overwrite the audit log through a tool command.

Symlink traversal and `../` injection are defeated at the math level: the canonical path must
resolve inside `reports/`, not merely start with the string.

---

### stdin isolation

All `subprocess.run` calls set `stdin=subprocess.DEVNULL`. The agent cannot read from stdin,
closing the piped prompt injection vector.

---

### Chain-of-custody audit log

Every command — allowed or blocked — is atomically appended to `reports/audit_log.jsonl` using
raw `os.open + os.write` before `subprocess.run` is called. Not Python's buffered IO — a
partial write cannot occur. Blocked commands log `blocked_reason`; successful commands log
timestamp, duration, returncode, and output preview.

---

### Read-only evidence mounts

Images are mounted `ro,norecovery` at the kernel level. Even if a command passed every
validator, the kernel blocks any write to `/mnt/<hostname>` at the syscall level. This is
stronger than a database role — it is not enforced by the application.

`norecovery` prevents the filesystem driver from replaying the journal on mount, which would
modify metadata even on a read-only image.

---

### Non-root agent execution

The agent runs as `sansforensics` — no `sudo` access. Image mounting requires elevated
privileges and is performed manually before investigation. The setup process and the
investigation process run with different privilege levels by design.

---

### Adversarial anti-hallucination layer

Above the command execution boundary, the Forensic Auditor provides a second architectural
defense against LLM reasoning errors. The Auditor receives only the findings list — no access
to the Triage Agent's reasoning — and independently re-runs its own tool calls against the same
evidence. A finding survives only if the Auditor can verify it with bytes on disk.

On the controller investigation this caught two false positives the Triage Agent scored at HIGH
confidence. Final score: 145 → 50. One confirmed technique, zero false accusations.

---

### Honest scope of the boundary

The validator prevents **writing, destroying, and exfiltrating**. It does not prevent the agent
from **reading** arbitrary files it has filesystem access to — `cat`, `grep`, `strings`, and
similar tools can read any path `sansforensics` can reach, including files outside the evidence
mount. For a SIFT exam workstation this is an accepted limitation: scoping reads to `/mnt/`
paths only would break legitimate forensic workflows. The read surface is acknowledged, not
claimed as protected.

---

## Datasets

Mordor/OTRF real Windows Sysmon telemetry is not included in this repo (1.3 GB).
Download instructions: [DATASET.md](DATASET.md)

---

## Cross-Dataset Validation

ADVERSA's rules contain two kinds of signals, tracked per-signal in `signals_tagged`:

- **`asl_trained`** — learned autonomously by the Red/Blue loop on Mordor/OTRF Sysmon data
- **`forensic_ioc`** — extracted from the SANS case and added back into the rules post-investigation

Only `asl_trained` signals are tested against independent data. Testing `forensic_ioc` signals
(case-specific C2 IPs, custom malware names like `hydrakatz` and `spinlock`) on new data is
circular — they were derived from the same case they are credited with detecting.

`validate_against_evtx.py` runs `asl_trained` signals against the EVTX-ATTACK-SAMPLES dataset
used by [Splunk Agentic IR](https://github.com/sassom2112/splunk-agentic-ir) — an independent
source never seen during training.

```bash
python3 validate_against_evtx.py   # uses ../splunk-agentic-ir by default
```

| Technique | Detected | ASL signals matched | IOC signals excluded |
|-----------|----------|--------------------|--------------------|
| T1003.001 — Credential Dumping | YES | mimikatz, comsvcs.dll, rundll32.exe, dbgcore.dll | hydrakatz, spinlock, spinlock.exe |
| T1569.002 — PsExec | YES | psexec, \\admin$\\ | psexesvc, PSEXESVC.EXE |
| T1547.001 — Registry Run Key | YES | WmiPrvSE.exe | psexesvc |
| T1548.002 — UAC Bypass | YES | fodhelper, consent.exe, powershell.exe | — |
| T1059.001 — PowerShell Execution | YES | svchost.exe | — |
| T1036.005 — Masquerading | NO | 0/4 ASL signals fired | — |
| T1087.001 — Account Discovery | NO | 0/20 ASL signals fired | vibranium, SHIELDBASE+vibranium |
| T1071.001 — C2 Web Protocol | N/A | 0 ASL signals (all signals are forensic IOCs) | 12.190.135.235, 199.73.28.114 |
| T1055 — Process Injection | N/A | 0 ASL signals (Zeus-specific IOCs only) | sdra64, ntos.exe, … |

**5 of 9 testable rules (55.6%)** detect on the independent dataset using only `asl_trained`
signals. T1036.005 and T1087.001 have ASL signals that did not fire — those techniques lack
process-create field coverage in this EVTX sample. T1071.001 and T1055 contain no generalizable
signals and are excluded from the rate.

Full per-signal results: `reports/evtx_cross_validation.json`

---

## License

MIT
