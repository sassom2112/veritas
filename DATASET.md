---
title: Dataset
nav_order: 6
permalink: /dataset
---

# Dataset Documentation

## Primary Training Corpus: OTRF/Mordor Security Datasets

The adversarial training loop is grounded exclusively in real attack-execution telemetry
from the [Open Threat Research Foundation (OTRF) Mordor project](https://github.com/OTRF/Security-Datasets).

| Property | Value |
|----------|-------|
| Source | OTRF/Security-Datasets (GitHub) |
| Format | Windows Sysmon JSONL |
| Discovery mechanism | MSTICPy `MordorDriver` — 113 metadata files indexed at runtime |
| Total events available | ~49,519 Sysmon events across all loaded datasets |
| Access method | HTTP download at training time; JSON cached in `mordor_cache.json` |

### Technique-to-Dataset Mapping

Each MITRE ATT&CK technique maps to one or more real Mordor execution recordings.

| Technique | Name | Dataset File(s) | Key Sysmon Fields |
|-----------|------|-----------------|-------------------|
| T1569.002 | PsExec | `lateral_movement/empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json` | TargetImage, SourceImage, CallTrace, GrantedAccess |
| T1547.001 | Registry Run Key | `persistence/empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json` | TargetObject, Details, EventType |
| T1003.001 | Credential Dumping | `credential_access/empire_mimikatz_logonpasswords_2020-08-07103224.json` | TargetImage, SourceImage, GrantedAccess, CallTrace |
| T1036.005 | Masquerading | `defense_evasion/empire_dllinjection_LoadLibrary_CreateRemoteThread_2020-07-22000048.json` | SourceImage, TargetImage, StartAddress, StartModule |
| T1071.001 | C2 Web Protocol | IOC-based (confirmed C2 IPs from case) | DestinationIp, DestinationPort |
| T1087.001 | Account Discovery | 6 datasets: SAMR enumeration, Seatbelt, net localgroup, GetDomainGroup | CommandLine, Image, AccountName |
| T1059.001 | PowerShell / VBS | 4 datasets: VBS launcher, SharpView, PowerShell HTTP listener | CommandLine, Image, ScriptBlockText |
| T1560.001 | Archive Collected Data | `collection/msf_record_mic_2020-06-09225055.json` | Image, TargetObject, TargetFilename |
| T1548.002 | UAC Bypass | 2 datasets: fodhelper, Fax service modification | Image, CommandLine, IntegrityLevel, TargetObject |

### MSTICPy Dynamic Discovery

At training time, `MSTICPyRedAgent` queries the live MSTICPy `MordorDriver` API:

```
driver.connect()                       # downloads 113 metadata YAML files
driver.search_queries('T1003')         # returns ~46 matching dataset names
```

Any dataset names that map to locally cached JSONL files are merged into the event pool,
expanding coverage beyond the baseline nine dataset files listed above.

---

## Case Investigation Data: nromanoff Host Image

The `blue_agent.py` investigator was developed and validated against a real case
image (SANS FOR508 course evidence).

| IOC Type | Value | Source |
|----------|-------|--------|
| Compromised account | vibranium (SID -1673) | Registry SAM hive |
| C2 IP | 12.190.135.235 | Network logs, registry winclient key |
| C2 IP | 199.73.28.114 | Network logs |
| C2 URI pattern | `/ads/` | Web proxy logs |
| Persistence tool | dllhost\svchost.exe run key | HKCU\...\Run |
| Lateral movement | PSEXESVC.EXE | %WINDIR%\PSEXESVC.EXE |
| Implant | spinlock.exe | MD5: 6bff2aebb8852fc2658b9768d2166ece |
| Anti-forensics | BCWipe | Installed application |
| Exfil archive | system4.rar | Found in user profile |

This data informs the `KNOWN_IOCS` dict in `blue_agent.py` and the `_KNOWN_C2_IPS`
set in `msticpy_enrichment.py`. It is used for cross-host IOC matching only —
no case artifacts are used as training inputs.

---

## Benign Baseline

To train the Blue Agent to reduce false positives, benign Windows process activity
is synthetically generated from `BENIGN_TEMPLATES` in `mordor_agent.py`. Templates
include:

- Windows Defender (`MsMpEng.exe`) accessing `svchost.exe` — legitimate process access
- `svchost.exe` accessing other `svchost.exe` instances — normal Windows behaviour
- Standard registry reads by trusted processes
- Routine network connections to RFC1918 addresses

The benign/attack ratio during training is configurable (`benign_ratio=0.43` default).
After 3,000 iterations the benign baseline produced 878 test events against which
the model recorded 725 false positives (FP rate ~17% at the final weights).

---

## Domain Gap: Simulated vs Real Telemetry

This was the critical research finding of the project.

**Observation**: When the Blue Agent was initially trained on simulated/synthetic
Sysmon events (hand-crafted templates), detection rates appeared near 100%.
When the training corpus was switched to real Mordor JSONL recordings, detection
collapsed to **~10%** at iteration 10.

**Why it matters**: Real Sysmon events contain:
- Noise fields not present in synthetic data (ProcessGuid, RuleName, UtcTime)
- Variable field ordering and encoding
- Benign processes with partially matching strings
- Mixed EventIDs in a single dataset file

**Resolution**: The adversarial loop was run for 3,000 iterations on real Mordor
events. The Blue Agent autonomously learned which field values were discriminating
(e.g., `CallTrace` content, `GrantedAccess` values) versus incidental noise.

Final result: **75% detection rate, F1 = 0.72** on real Mordor telemetry.

---

## Dataset Integrity

All Mordor JSONL files are read-only training inputs. No modification is made
to any dataset file at any point. The `MordorRedAgent` loads events via
`json.loads()` and copies them into memory — the source files are never written.

The ASL training state (learned signals, weights, evasion variants) is written
exclusively to `reports/brain_state.json` and `reports/patterns.db`.
