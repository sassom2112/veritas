---
nav_exclude: true
---

# Domain Gap — VERITAS Signal Calibration

## The Problem

Sysmon-trained signals have ~27% recall when applied to SIFT disk forensic
tool output. Sysmon references Windows event fields invisible in disk forensics:

```
Sysmon signal:        EventID=8, GrantedAccess=0x1fffff, Host=WS01
SIFT disk output:     sekurlsa::logonpasswords | FLS: lsass.dmp
```

Same attack (T1003.001), zero token overlap. A model trained on Sysmon
never learns to say "lsass.dmp".

## The Solution

Replaced the ASL training loop with corpus-calibrated log-odds weights derived
from real malware samples:

| Source | Samples | Labels |
|---|---|---|
| MalwareBazaar | ~600 | MITRE technique tags via SHA256 metadata |
| HybridAnalysis | ~200 | vx_family, submit_name, behavioral tags |

**Scoring model:**
```
log_odds = log2( (p_malware + 0.05) / (p_benign + 0.05) )
weight   = normalize(log_odds) → [0, 1]
```

Cross-technique tokens (appearing in 4+ technique corpora) capped at 0.2.
Confirmed case signals retain a floor weight of 0.5.

## Training Data Provenance

| Source | Auditable? |
|---|---|
| MalwareBazaar | Yes — public threat intel, SHA256 traceable |
| HybridAnalysis | Yes — public sandbox, SHA256 traceable |
| Benign baseline | Yes — curated Windows system string list in compute_weights.py |

All signals are transparent substring matches. Each finding independently
re-verified by `auditor_agent.py`.

## Per-Technique Coverage

From `data/calibrated_weights.json`:

| Technique | Top Signals | Weight |
|---|---|---|
| T1003.001 | mimikatz, sekurlsa, hydrakatz | 1.0 |
| T1003.002 | mimikatz, sekurlsa | 1.0 |
| T1059.001 | powershell, invoke-expression | 1.0 |
| T1087.001 | sharphound, hound, attack-tool | 1.0 |
| T1547.001 | autorun | 0.982 |
| T1560.001 | 7zip | 0.992 |
| T1569.002 | psexesvc, psexec, \admin$\ | 0.877 |
| T1071.001 | cobalt, beacon, cobaltstrike | 0.611 |
| T1548.002 | uacme, uacbypass | 1.0 |
