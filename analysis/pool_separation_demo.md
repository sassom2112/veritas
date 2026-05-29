---
nav_exclude: true
---

# Pool Separation Demo — Discriminative Signal Extraction

**Source:** Mordor attack datasets + BENIGN_TEMPLATES in mordor_agent.py  
**Generated:** 2026-05-15T06:37:56Z  
**Current signals evaluated:** 83 (from operational_rules.json)  

## Methodology

For each MITRE technique:
1. Extract all string field values from every Mordor attack event (attack pool).
2. Extract all string field values from BENIGN_TEMPLATES (benign pool).
3. Compute: `discriminative = attack_pool_values - benign_pool_values`
4. Classify each current signal as:
   - **Surviving** — present in attack pool, absent from benign pool (safe to use)
   - **FP risk** — present in benign pool (would fire on benign events)
   - **Not in Mordor** — not found in either pool (campaign-specific IOC or synthetic)


> **Caveat on benign pool strength:**
> The current benign pool contains 7 synthetic Windows event templates.
> A production-grade filter requires a real baseline (e.g., BETH dataset, ~1M events).
> Results below demonstrate the *methodology* and structural approach.
> FP-risk classifications may be underestimated due to the thin benign baseline.

---

## T1003.001 — Credential Dumping

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 2 | 20% |
| FP risk (in benign pool) | 2 | 20% |
| Campaign-specific / not in Mordor | 6 | 60% |

**Surviving signals (safe):**
- `0x1fffff`
- `lsass memory read op`

**FP-risk signals (appear in benign pool):**
- `\device\harddiskvolume2\windows\system32\lsass.exe`
- `query user`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `comsvcs.dll`
- `dbgcore.dll`
- `hydrakatz`
- `mimikatz`
- `rundll32.exe`

---

## T1036.005 — Masquerading

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 2 | 29% |
| FP risk (in benign pool) | 5 | 71% |
| Campaign-specific / not in Mordor | 0 | 0% |

**Surviving signals (safe):**
- `WmiPrvSE.exe`
- `wmiprvse.exe`

**FP-risk signals (appear in benign pool):**
- `SystemCertificates\Disallowed`
- `\Registry\Machine\Software\Classes\CLSID\`
- `\device\harddiskvolume4\windows\system32\lsass.exe`
- `dllhost\\svchost.exe`
- `svchost.exe`

---

## T1059.001 — PowerShell / VBS Execution

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 7 | 70% |
| FP risk (in benign pool) | 2 | 20% |
| Campaign-specific / not in Mordor | 1 | 10% |

**Surviving signals (safe):**
- `4658`
- `4663`
- `Explorer.exe accessing lsass with PROCESS_QUERY_LIMITED_INFORMATION`
- `Image=C:\ProgramData\SharpView.exe`
- `Services\TCPIP6\Parameters`
- `invoke-expression`
- `powershell -enc`

**FP-risk signals (appear in benign pool):**
- `Image=C:\Windows\System32\cmd.exe | EventID=17 | Host=WS01`
- `svchost.exe`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `-win 1 -enc`

---

## T1071.001 — C2 Web Protocol

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 0 | 0% |
| FP risk (in benign pool) | 0 | 0% |
| Campaign-specific / not in Mordor | 3 | 100% |

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `12.190.135.235`
- `199.73.28.114`
- `winclient`

---

## T1087.001 — Account Discovery

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 8 | 36% |
| FP risk (in benign pool) | 8 | 36% |
| Campaign-specific / not in Mordor | 6 | 27% |

**Surviving signals (safe):**
- `4656`
- `5156`
- `SDXHelper.exe`
- `SeSecurityPrivilege`
- `Win32_Account`
- `WmiPrvSE.exe`
- `psmserviceexthost.dll`
- `samr`

**FP-risk signals (appear in benign pool):**
- `HKLM\System\CurrentControlSet\Services\W32Time`
- `Win32_UserAccount`
- `lsass.exe`
- `net user /domain`
- `query.exe user /domain`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `5381`
- `[adsisearcher]`
- `port 445`
- `regsvr32.exe /s /n /u /i:scrobj.dll`
- `tasklist.exe /FO CSV`

---

## T1547.001 — Registry Run Key

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 1 | 14% |
| FP risk (in benign pool) | 2 | 29% |
| Campaign-specific / not in Mordor | 4 | 57% |

**Surviving signals (safe):**
- `WmiPrvSE.exe`

**FP-risk signals (appear in benign pool):**
- `Set-ItemProperty HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `\lsass`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `EventID=5156`
- `Network conn allowed via kernel filter layer SourcePort:445`
- `dllhost\\svchost`
- `psexesvc`

---

## T1548.002 — UAC Bypass

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 2 | 22% |
| FP risk (in benign pool) | 5 | 56% |
| Campaign-specific / not in Mordor | 2 | 22% |

**Surviving signals (safe):**
- `consent.exe`
- `fodhelper`

**FP-risk signals (appear in benign pool):**
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `C:\Windows\System32\cmd.exe /c whoami > C:\temp\out.txt`
- `HKLM\SOFTWARE\Microsoft`
- `Image=System | EventID=9`
- `Image=System | TargetObject=HKLM\SOFTWARE\Classes\CLSID | EventID=12`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `ComputerDefaults.exe`
- `Object handle closed via indirect syscall NtClose stub`

---

## T1560.001 — Archive Collected Data

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 4 | 67% |
| FP risk (in benign pool) | 1 | 17% |
| Campaign-specific / not in Mordor | 1 | 17% |

**Surviving signals (safe):**
- `RuntimeBroker.exe`
- `SearchIndexer.exe`
- `audiocapture`
- `taskhostw.exe`

**FP-risk signals (appear in benign pool):**
- `\REGISTRY\A\{9b5e4ab2-4045-b3ce-47fb-1bc6929617ea}\LocalState`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `record_mic`

---

## T1569.002 — PsExec

| Category | Count | % of signals |
|----------|-------|--------------|
| Surviving (discriminative) | 4 | 44% |
| FP risk (in benign pool) | 0 | 0% |
| Campaign-specific / not in Mordor | 5 | 56% |

**Surviving signals (safe):**
- `DeliveryOptimization\Usage`
- `NetworkSetup2\BindPaths`
- `psexec`
- `sc.exe start RemoteRegistry`

**Campaign-specific (not in Mordor — likely nromanoff IOCs):**
- `EventID=10`
- `\admin$\`
- `psexesvc`
- `pwsh.exe`
- `sc.exe create`

---

## Summary

| | Count | % |
|---|---|---|
| Total current signals | 83 | 100% |
| Would survive pool filter | 30 | 36% |
| FP risk (in benign pool) | 25 | 30% |
| Campaign-specific IOCs | 28 | 34% |

## Architectural Implication

Signals in the **surviving** category are discriminative by construction:
they appear in documented attack telemetry and are absent from the benign baseline.
No hallucination possible at extraction — the value is present in real Sysmon data.

Signals in the **campaign-specific** category are the generalization gap:
they detect the nromanoff/Mordor campaigns specifically, not the technique generally.
A new campaign with different tooling would produce zero hits from these signals.

The **production fix** is pool separation against a real benign baseline (BETH):
    discriminative_signals = field_values(Mordor[T]) - field_values(BETH)
This makes false signal introduction structurally impossible and campaign-specific
IOCs identifiable at training time, not after deployment.
