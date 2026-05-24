# Domain Gap Results — ADVERSA Forensic Detection

## Core Empirical Finding

Sysmon-trained ASL signals have ~27% recall when applied to SIFT disk forensic
tool output. After retraining on disk-format artifacts, recall rises to 60% at
1000 iterations and continues improving.

| Phase | Commit | Detection | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Sysmon domain baseline (no disk training) | `fd72930` | ~27% | ~100% | ~27% | ~0.42 |
| Disk domain — 500 iterations | `d150285` | 42% | 100% | 42% | 0.59 |
| Disk domain — 1000 iterations | `7b23051` | 60% | 100% | 60% | 0.75 |

Tags: `v0.1-sysmon-asl-baseline`, `v0.2-disk-domain-added`, `v0.3-disk-domain-60pct-recall`

## Why the Domain Gap Exists

Sysmon signals reference Windows event fields that are invisible in disk forensics:

```
Sysmon signal (brain_state.json):   EventID=8, GrantedAccess=0x1fffff, Host=WS01
SIFT disk tool output (strings):    sekurlsa::logonpasswords | FLS: lsass.dmp
```

These are the same attack (T1003.001 LSASS dump) but the observable strings
have zero overlap. A model trained only on Sysmon never learns to say "lsass.dmp".

## Training Data Provenance (Forensic Admissibility)

| Source | Type | Auditable? |
|---|---|---|
| MalwareBazaar | Real malware SHA256s + file metadata | Yes — public threat intel repo, SHA256 traceable |
| Hybrid Analysis | Static PE metadata (submit_name, type, vx_family) | Yes — public sandbox, SHA256 traceable |
| Seed data (`forensic_red_agent.py`) | Hand-crafted SIFT-format artifacts per ATT&CK technique | Yes — in git history, author-controlled |

All signals are transparent substring matches — not black-box weights.
Each finding independently re-verified by `auditor_agent.py`.

## Per-Technique Results at 1000 Iterations

From `reports/forensic_accuracy_report.json`:

| Technique | Name | Weight | Signals |
|---|---|---|---|
| T1003.001 | Credential Dumping (LSASS) | 50 | mimikatz, sekurlsa, lsass.dmp, procdump, comsvcs.dll |
| T1547.001 | Registry Run Key | 50 | currentversion\run, currentversion\runonce, dllhost/svchost |
| T1569.002 | PsExec | 50 | psexesvc, psexec, \\admin$, remcomsvc |
| T1036.005 | Binary Masquerading | 40 | 102400, dllhost/svchost.exe, upx, wrong imports |
| T1087.001 | Account Discovery | 50 | seatbelt, sharpview, enumdomainusers, getdomaingroup, bloodhound |
| T1059.001 | PowerShell Execution | 50 | invoke-expression, frombase64string, iex |
| T1548.002 | UAC Bypass | 45 | fodhelper, sdclt, ms-settings\shell\open, eventvwr |
| T1560.001 | Data Archival | 50 | winrar, rar.exe, 7za.exe, .rar, .7z |

T1036.005 and T1548.002 at lower weights — need more training or real HA dynamic reports.

## Three-Workstream Convergence (Novel Contribution)

No prior tool uses ASL-trained signals across all three forensic output domains
on a single investigation:

1. **Sysmon domain** (`brain.py` + Mordor dataset) — live system events
2. **Disk forensic domain** (`forensic_brain.py` + MalwareBazaar/HA) — post-incident artifacts
3. **Memory domain** (`memory_agent.py` + Volatility 3) — runtime process state

`blue_agent.py` (two-pass: deterministic signal match + Claude agentic reasoning)
correlates hits across all three. `auditor_agent.py` independently re-verifies.
`operational_rules.json` merges patterns from all domains with source tags.

## Next Training Milestones

- 1500 iterations: projected ~70% recall (extrapolating +18 pts/500 iter curve)
- Fix T1036.005: path separator normalization now corrected — will recover on next run
- HA dynamic reports: require `/report/{sha}/behavior` endpoint (dynamic sandbox tier)
- Volatility ISF symbols: Win7 x64 symbols needed for nfury memory score
