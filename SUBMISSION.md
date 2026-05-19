---
title: Try It Out
nav_order: 2
permalink: /submission
---

# Try It Out

ADVERSA runs on a SANS SIFT workstation against mounted Windows disk images. There is no hosted demo — the tool calls real forensic binaries (`vol.py`, `fls`, `rip.pl`, `grep`) directly against evidence files. That's the point.

---

## Watch It Self-Correct

The most compelling run is the **controller** host from the SANS FIND EVIL! 2026 case set. The Triage Agent flags three techniques with a score of 145. The Forensic Auditor independently challenges each one. Two are false positives. One is confirmed on disk.

**Triage Agent — Phase 1 output:**

```
════════════════════════════════════════════════════════════
  ADVERSARIAL INVESTIGATION ORCHESTRATOR
  Framework:  ADVERSA (Adversarial Signal Learning)
  Target:     /mnt/controller
  Started:    2026-05-15T21:28:40Z
════════════════════════════════════════════════════════════

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 1  —  TRIAGE AGENT  (The Optimist)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Pass 1: deterministic sweep — 24 tool calls

  Score: 145/100  →  HIGH
    • Masquerading         (+50) [ASL] via: ['WmiPrvSE.exe', 'wmiprvse.exe', 'svchost.exe']
    • Credential Dumping   (+50) [ASL] via: ['procdump', 'spinlock', 'spinlock.exe']
    • Account Discovery    (+45) [ASL] via: ['WmiPrvSE.exe', 'vibranium', 'SHIELDBASE+vibranium']
```

Three techniques flagged. Score 145. If this were a traditional triage tool, an analyst would open three investigations. ADVERSA sends the findings to the Auditor instead.

---

**Forensic Auditor — Phase 2, challenging each finding:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 2  —  FORENSIC AUDITOR  (The Cynic)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Challenging T1036.005 — Masquerading
    Round 1: find_suspicious_executables + check_known_iocs
    Artifact found: svchost.exe in
      /Windows/winsxs/amd64_microsoft-windows-services-svchost_.../svchost.exe
    ✗ REFUTED — WinSxS is a legitimate Windows component store.
                No masqueraded binary outside System32 or WinSxS.

  Challenging T1003.001 — Credential Dumping
    Round 1: get_credential_artifacts + find_suspicious_executables
    Artifact found: /mnt/controller/Tools/SysInternals/procdump.exe
                    /mnt/controller/Windows/System32/config/SAM
    ✓ CONFIRMED — procdump.exe on disk. SAM hive accessible.
                  spinlock.exe WER crash artifact in ReportQueue.

  Challenging T1087.001 — Account Discovery
    Round 1: check_known_iocs + run_terminal_command
    Artifact found: /mnt/controller/Users/vibranium/ (profile directory)
    ✗ REFUTED — WmiPrvSE.exe is a legitimate Windows process.
                vibranium is a user profile, not an enumeration tool.
                No net.exe, dsquery, or SAMR calls found on disk.
```

---

**Final result:**

```
════════════════════════════════════════════════════════════
  INVESTIGATION COMPLETE  (397s)

  Triage score:          145
  After audit:           50
  Confirmed techniques:  ['T1003.001']
  Inconclusive:          []
  Refuted  techniques:   ['T1036.005', 'T1087.001']
  Argumentation rounds:  5
  Final verdict:         HIGH — Active compromise confirmed
                         (high-value technique verified on disk)

  Reports written:
    Triage     →  reports/controller-custom-agent-report.json
    Transcript →  reports/controller-auditor-transcript.json
    Unified    →  reports/controller-investigation.json
    HTML       →  reports/controller-report.html
    IOCs       →  reports/controller-iocs.json
════════════════════════════════════════════════════════════
```

The Auditor saved an analyst two false investigation threads. The one confirmed finding — `procdump.exe` staged at `Tools/SysInternals/` alongside a WER crash artifact from `spinlock.exe` — is real and on disk. Score 145 → 50. Both false positives caught without human review.

---

## Setup

```bash
# SANS SIFT workstation (Ubuntu) recommended
python3 -m venv ~/adversa-env && source ~/adversa-env/bin/activate
pip install anthropic mcp matplotlib numpy

export ANTHROPIC_API_KEY="sk-ant-..."
```

Requires a Windows disk image mounted read-only at a path like `/mnt/hostname`.

---

## Path A — Fast triage, no API key (< 10 seconds)

```bash
python3 fast-triage/fast_triage.py /mnt/hostname
```

Deterministic IOC sweep using pre-trained ASL rules. Prints score and matched signals. Auto-escalates to full pipeline if score ≥ 30.

---

## Path B — Full adversarial pipeline

```bash
# Terminal 1
python3 custom-agent/sift_server.py

# Terminal 2
python3 custom-agent/investigate.py /mnt/hostname
```

Runs Triage → Auditor → HTML report. IOCs auto-carry to the next host.

**Campaign mode** — IOCs from completed hosts are auto-detected:

```bash
python3 custom-agent/investigate.py /mnt/host1
python3 custom-agent/investigate.py /mnt/host2   # host1 IOCs injected automatically
python3 custom-agent/investigate.py /mnt/host3   # host1 + host2 IOCs
```

---

## Path C — Retrain ASL on new evidence

```bash
python3 custom-agent/brain.py                 # ~30 min, 3000 iterations
python3 custom-agent/export_patterns.py       # → operational_rules.json
python3 custom-agent/sigma_exporter.py        # → reports/sigma_rules/*.yml
```

Download Mordor datasets first: [DATASET](dataset)

---

## Output files

| File | What it contains |
|------|-----------------|
| `reports/hostname-report.html` | Full investigation report — exec summary, IOC table, Auditor transcript |
| `reports/hostname-investigation.json` | Confirmed / inconclusive / refuted techniques, adjusted score |
| `reports/hostname-auditor-transcript.json` | Every Auditor challenge, round-by-round, with tool output and reasoning |
| `reports/operational_rules.json` | Pre-trained ASL rules — ship with the repo, no training required to use |
| `reports/sigma_rules/*.yml` | Sigma detection rules, adversarially validated |
