---
title: Accuracy & Evidence Integrity
nav_order: 5
permalink: /accuracy
---

# Accuracy & Evidence Integrity

## Final Training Metrics (3,000 Iterations)

| Metric | Value |
|--------|-------|
| Total training iterations | 3,000 |
| Detection rate (recall) | 75% |
| Precision | 69% |
| F1 score | 0.72 |
| Total attack events tested | 2,122 |
| Total detections | 1,592 |
| Total misses | 530 |
| False positives | 725 / 878 benign events |
| Red evasion variants survived | 1,245 |
| Signals learned autonomously | 83 |

### Per-Technique Results

| Technique | Name | Detection Rate | Patterns Learned | Red Evasions |
|-----------|------|---------------|-----------------|--------------|
| T1547.001 | Registry Run Key | 70% | 7 | 148 |
| T1036.005 | Masquerading | **81%** | 7 | 171 |
| T1003.001 | Credential Dumping | 73% | 10 | 159 |
| T1569.002 | PsExec | **82%** | 9 | 173 |
| T1087.001 | Account Discovery | 74% | **22** | 162 |
| T1059.001 | PowerShell/VBS Exec | 71% | 10 | 139 |
| T1560.001 | Archive Collected Data | 74% | 6 | 145 |
| T1548.002 | UAC Bypass | 76% | 9 | 148 |

T1071.001 (C2 Web Protocol) uses IOC-based protected signals and is not counted
in the autonomous-learning metrics above.

---

## Learning Progression

Detection rate measured at key iteration checkpoints. All measurements are on
real OTRF/Mordor Sysmon events — not simulated data.

| Checkpoint | Detection Rate | Notes |
|-----------|---------------|-------|
| Iteration 10 | ~10% | Domain gap — real Sysmon telemetry loaded; synthetic patterns useless |
| Iteration 50 | ~28% | Blue Agent begins discovering registry field patterns |
| Iteration 100 | ~41% | First stable signals in T1569.002 and T1003.001 |
| Iteration 200 | ~52% | Cross-technique signal sharing starts; T1036.005 rises |
| Iteration 500 | ~62% | Red evasion variants forcing Blue Agent to diversify signals |
| Iteration 1,000 | ~68% | Signal pruning removes noise; protected IOC signals stabilise |
| Iteration 1,500 | ~71% | F1 reported at 0.72; 4 techniques above 70% |
| Iteration 2,000 | ~73% | T1036.005 and T1569.002 break 80% |
| Iteration 3,000 | **75%** | Final weights; 22 signals for T1087.001 (highest diversity) |

**Key insight**: The jump from 10% to 41% occurred autonomously with no human
intervention — the adversarial loop self-corrects by having the Red Agent evolve
evasions when caught and the Blue Agent add new signals when it misses. No human
labels, feature engineering, or model retraining was performed.

---

## Grounded Learning: No Hallucination

This is an architectural guarantee, not a configuration setting.

The Blue Agent learns patterns from real Sysmon events by extracting signal strings
that are **literally present in the raw JSON event**. Claude is given the raw event
dict and asked to extract the field values it observes. If a value is not in the
event, Claude cannot fabricate it because the scoring function does exact substring
matching against the actual artifact string.

The Red Agent (`MordorRedAgent`) draws artifacts exclusively from the JSONL files —
it never generates synthetic text. The artifact string passed to the Blue Agent is
a field-formatted slice of a real Sysmon record.

**Result**: Every signal in `reports/operational_rules.json` traces directly to a
field value observed in real Mordor telemetry. There are no hallucinated IOCs.

---

## Evidence Integrity Architecture

The project enforces forensic evidence integrity at multiple layers:

### Layer 1: Filesystem Access Control (CLAUDE.md)

Operator instructions prohibit any write to `/cases/`, `/mnt/`, `/media/`, or
`evidence/` directories. All output is routed to `./analysis/`, `./exports/`,
or `./reports/`.

### Layer 2: MCP Command Validation (sift_server.py)

Every shell command executed by the Blue Agent passes through a four-stage validator.
This is **architectural enforcement**, not prompt-based — the model cannot override it:

1. **Hard-blocked substrings** — `shred`, `mkfs`, `dd if=/dev/zero`, `wget`, `curl`,
   `nc`, `ssh`, `scp`, `sudo`, `kill`, `$(`, backtick and 11 others are blocked
   unconditionally, regardless of context.

2. **Binary allowlist** — Each pipeline segment (split on `|`) must start with a
   binary from a hardcoded frozenset of forensic tools (~50 entries: `grep`, `fls`,
   `vol.py`, `rip.pl`, `strings`, `md5sum`, `xxd`, etc.). Unlisted binaries (`rm`,
   `chmod`, `xargs`, etc.) are rejected.

3. **Quote-aware pipe parser** — Pipes inside quoted strings are not treated as
   segment boundaries, preventing injection via `"cmd1 | rm -rf"`-style arguments.

4. **Path-restricted redirection** — Any `>` or `>>` redirection target is resolved
   with `os.path.realpath()`. The resolved path must fall inside the `_REPORTS`
   directory. Redirections to `/dev/null`, `../` traversals, and evidence paths
   are blocked.

All validation decisions are written to an atomic audit log via `os.O_APPEND`
for chain-of-custody integrity.

### Prompt-Based vs Architectural Guardrails

| Guardrail | Type | What happens if model ignores it? |
|-----------|------|-----------------------------------|
| CLAUDE.md operator instructions (no writes to `/cases/`) | **Prompt-based** | If the model ignores the instruction, the MCP validator (Layer 2) still blocks any `>` redirect targeting `/cases/` or `/mnt/`. The architectural layer provides the actual protection. |
| Agent system prompts ("only report confirmed findings") | **Prompt-based** | A hallucinated finding that bypasses the agent's own skepticism will still be challenged by the Forensic Auditor, which independently runs SIFT commands. If the artifact is not on disk, the technique is marked INCONCLUSIVE or REFUTED. |
| MCP binary allowlist | **Architectural** | Cannot be overridden by any prompt. Enforced in Python before `subprocess.run()`. |
| MCP redirect guard | **Architectural** | Cannot be overridden by any prompt. `os.path.realpath()` resolves symlinks before the path check. |
| Auditor independence | **Architectural** | The Auditor opens a separate MCP session with no shared state with the Triage Agent. A CONFIRMED verdict requires a positive `grep`/`find` result — no amount of model confidence produces CONFIRMED without a tool return value. |

### Layer 3: Read-Only Dataset Access

`MordorRedAgent` opens all JSONL files in read mode. The training loop writes
learned state only to `reports/brain_state.json` and `reports/patterns.db`.

### Layer 4: Protected Signals

Forensically confirmed IOCs (C2 IPs, known tool names, confirmed account names)
are stored as `protected_signals` in `brain_state.json`. The signal pruning step
— which removes low-hit-rate signals — explicitly skips protected signals. They
cannot be removed by the adaptive training loop even if they appear in benign
contexts due to evasion.

---

## False Positive Analysis

FP rate: 725 false positives on 878 benign events (~83% raw FP rate).

This number looks alarming but reflects deliberate training trade-offs:

1. **Additive scoring**: The scoring engine sums weights from all matching techniques.
   A single benign event that contains one word matching any signal across all 8
   techniques contributes to the FP count.

2. **Threshold calibration**: At the `HIGH` confidence threshold (score ≥ 70),
   precision rises significantly — the FP rate on combined scores is lower than
   the per-signal rate suggests.

3. **Context is available**: `blue_agent.py` presents a structured breakdown of
   which signals matched with what weights. An analyst can review the signal list
   to determine whether a positive is genuine or coincidental.

4. **Trade-off is intentional**: In a forensic IR context, a missed true positive
   (attacker not detected) has higher cost than a false positive (analyst reviews
   a benign event). The training rewards detection rate over precision.

The two-pass self-correction in `blue_agent.py` partially mitigates FPs by
running deeper targeted scans only when the score is ambiguous (30–70), allowing
the agent to either confirm or dismiss partial matches before escalating.

The Forensic Auditor independently refuted two triage FPs on the controller host:
T1036.005 (masquerading) and T1087.001 (account discovery) were scored by the Triage
Agent but REFUTED when the Auditor found no physical artifacts on disk to support
either finding. Both false positives were caught without human review.

---

## Spoliation Testing

**Was the evidence boundary tested?** Observationally, during live investigation runs.

During all four host investigations (`nromanoff`, `tdungan`, `nfury`, `controller`),
the evidence directories (`/mnt/`, `/cases/`) were monitored for writes. No writes
were observed. All output was routed to `reports/` as designed.

### What the architecture guarantees (and how to verify)

The `_validate_command()` function in `sift_server.py` is the enforcement point.
To verify it independently:

```python
# Any command targeting /mnt or /cases is rejected by the redirect guard
from sift_server import _validate_command
_validate_command("grep foo /mnt/host > /mnt/host/out.txt")  # raises ValueError
_validate_command("rm -rf /mnt/host")                         # rejected by allowlist
_validate_command("grep foo /mnt/host | tee /tmp/x")          # 'tee' not on allowlist
```

### Documented limitation

The operator-level prompt restrictions (CLAUDE.md: "never write to /cases/") are
**prompt-based**, not architectural. If the MCP validator were disabled, these
restrictions would be the only barrier, and they can be ignored by the model. This
is the honest failure mode. The architectural Layer 2 validator exists precisely
because prompt-based restrictions are insufficient as the sole protection.

No deliberate adversarial bypass testing of the prompt-only configuration was
performed during this hackathon submission. That remains future work.
