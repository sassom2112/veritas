#!/usr/bin/env python3
"""
forensic_red_agent.py — Forensic-domain Red Agent for disk artifact ASL training.

Produces SIFT-format attack artifact descriptions for ForensicBrain discrimination.
Domain: disk forensic artifacts — strings tool output, fls filesystem listings,
rip.pl/RegRipper registry dumps, prefetch references.  NOT Sysmon event logs.

Seed dataset (~10 examples per technique) lets training start immediately without
any API key.  Run forensic_data_agent.py --fetch --all to enrich with Hybrid Analysis
sandbox data and increase training coverage.
"""
from __future__ import annotations

import json
import os
import random
import time

_HERE         = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, '..'))
_FORENSIC_DS  = os.path.join(_PROJECT_ROOT, 'datasets', 'forensic')

# ---------------------------------------------------------------------------
# Seed artifacts — SIFT-tool-format ground truth, one entry per example.
# Format mirrors what blue_agent.py reads:
#   STRINGS: <space-separated strings from 'strings' command>
#   FLS: <path (optional size/hash)>   — Sleuth Kit fls output
#   REG SET/DEL: <key> = <value>       — RegRipper rip.pl output
#   PREFETCH: <prefetch filename>
# ---------------------------------------------------------------------------
_SEED: dict[str, list[str]] = {
    'T1003.001': [
        'STRINGS: mimikatz sekurlsa::logonpasswords wdigest kerberos lsasrv.dll\nFLS: Windows/Temp/lsass.dmp',
        'STRINGS: procdump64 MiniDumpWriteDump OpenProcess lsass.exe ntdll.dll\nFLS: Windows/Temp/lsass.DMP',
        'STRINGS: comsvcs.dll MiniDump lsasrv kerberos cryptbase sekurlsa\nREG SET: HKLM\\SECURITY\\SAM',
        'STRINGS: wce.exe wdigest ntlm kerberos kerberos hash\nFLS: Windows/Temp/wce-output.txt',
        'FLS: Windows/Temp/lsass.dmp (size 75497472)\nSTRINGS: procdump memory dump LSASS',
        'STRINGS: sekurlsa wdigest tspkg livessp cloudap ssp credman\nFLS: AppData/Local/Temp/dump.bin',
        'FLS: Windows/System32/hydrakatz.exe (size 102400)\nSTRINGS: mimikatz sekurlsa logonpasswords',
        'STRINGS: privilege::debug sekurlsa::logonpasswords token::elevate\nFLS: Windows/Temp/mimikatz.log',
        'STRINGS: Invoke-Mimikatz sekurlsa kerberos logonPasswords download\nFLS: Temp/pwds.txt',
        'REG SET: HKLM\\SECURITY\\SAM\nSTRINGS: comsvcs MiniDump lsass 808 full',
    ],
    'T1547.001': [
        'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost = C:\\Windows\\dllhost\\svchost.exe\nFLS: Windows/dllhost/svchost.exe',
        'REG SET: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\update = C:\\Users\\Public\\updater.exe\nFLS: Users/Public/updater.exe',
        'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\task = cmd.exe /c rundll32\nSTRINGS: rundll32 regsvr32 persistence',
        'FLS: Windows/dllhost/svchost.exe (size 102400)\nREG SET: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost = dllhost\\svchost.exe',
        'REG: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nLastWrite: 2012-04-04\nsvchost = dllhost\\svchost.exe',
        'STRINGS: Software\\Microsoft\\Windows\\CurrentVersion\\Run RegSetValueExW autostart\nFLS: Windows/Temp/dropper.exe',
        'REG SET: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware = %APPDATA%\\payload.exe\nFLS: AppData/Roaming/payload.exe',
        'FLS: Windows/System32/config/SOFTWARE\nREG: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\persist = malicious.exe',
        'REG SET: HKLM\\SYSTEM\\CurrentControlSet\\Services\\malserv\\ImagePath = C:\\Windows\\malserv.exe\nFLS: Windows/malserv.exe',
        'STRINGS: CurrentVersion\\Run autorun persistence registry write autostart\nFLS: Temp/install.exe',
    ],
    'T1569.002': [
        'FLS: Windows/PSEXESVC.EXE\nSTRINGS: psexesvc RemComSvc \\\\admin$ svcctl CreateService',
        'STRINGS: psexec \\\\admin$\\\\PSEXESVC.EXE service install execute lateral\nFLS: Windows/PSEXESVC.EXE',
        'REG SET: SYSTEM\\CurrentControlSet\\Services\\PSEXESVC\\ImagePath = C:\\Windows\\PSEXESVC.EXE\nSTRINGS: RemComSvc psexesvc',
        'FLS: Windows/PSEXESVC.EXE (size 220160)\nREG SET: SYSTEM\\CurrentControlSet\\Services\\PSEXESVC\\Start = 3',
        'STRINGS: PsExec.exe \\\\target\\\\admin$ cmd.exe /c ipconfig lateral movement\nFLS: Windows/PSEXESVC.EXE',
        'STRINGS: RemComSvc psexesvc SYSTEM CreateService OpenSCManager DCE/RPC\nREG SET: Services\\PSEXESVC',
        'REG: HKLM\\SYSTEM\\CurrentControlSet\\Services\\PSEXESVC\nType = 272 Start = 3\nImagePath = C:\\Windows\\PSEXESVC.EXE',
        'STRINGS: psexec -s -i cmd.exe \\\\admin$ lateral execute\nFLS: Windows/Temp/psexec.exe Windows/PSEXESVC.EXE',
        'FLS: Windows/PSEXESVC.EXE Windows/Temp/psexec.exe\nSTRINGS: psexesvc lateral movement admin share',
        'STRINGS: svcctl DCE/RPC LAN Manager CreateService OpenSCManager psexec\nFLS: Windows/PSEXESVC.EXE',
    ],
    'T1036.005': [
        'FLS: Windows/System32/dllhost/svchost.exe (size 102400)\nSTRINGS: This program cannot be run in DOS mode wrong version',
        'STRINGS: PE32 wrong CompanyName wrong ProductVersion fake svchost masquerade\nFLS: Windows/System32/dllhost/svchost.exe',
        'FLS: Windows/Temp/svch0st.exe\nSTRINGS: MessageBoxW GetProcAddress LoadLibraryA shellcode inject',
        'STRINGS: UPX0 UPX1 UPX2 packed PE wrong section alignment\nFLS: Windows/System32/svchost32.exe',
        'FLS: Windows/System32/lsasrv32.dll (size 8192)\nSTRINGS: compact size mismatch version spoof shell',
        'STRINGS: wrong PE imports for claimed svchost CompanyName mismatch FileDescription\nFLS: dllhost/svchost.exe',
        'FLS: Windows/dllhost/svchost.exe\nSTRINGS: wrong import table wrong compile timestamp masquerade',
        'STRINGS: explorer.exe masquerade wrong path wrong parent wrong hash\nFLS: Users/Public/explorer.exe',
        'FLS: ProgramData/Microsoft/Windows/svchost.exe (non-standard location)\nSTRINGS: RAT payload shell',
        'STRINGS: cmd.exe renamed binary wrong version wrong icon masquerade\nFLS: Windows/Temp/svchost.exe (size 204800)',
    ],
    'T1087.001': [
        'FLS: Windows/Temp/seatbelt.exe\nSTRINGS: Seatbelt GetDomainGroup EnumDomainUsers LocalGroup Administrators',
        'STRINGS: SharpView Get-DomainUser Get-NetGroup Get-NetComputer BloodHound\nFLS: Windows/Temp/sharpview.exe',
        'STRINGS: net.exe user /domain samaccountname enumeration LocalGroup\nPREFETCH: NET.EXE-HASH.pf NET1.EXE-HASH.pf',
        'FLS: Windows/Prefetch/NET.EXE-HASH.pf\nSTRINGS: net user /domain localgroup administrators enum',
        'STRINGS: SamConnect SamEnumDomains SamOpenDomain GetGroupsForUser SAMR\nFLS: Windows/Temp/recon.exe',
        'STRINGS: SAMR EnumDomainUsers NTLM authentication domain accounts samaccountname\nFLS: Temp/enum.exe',
        'FLS: Windows/Temp/adrecon.exe\nSTRINGS: ActiveDirectory Get-ADUser Get-ADGroup ADRecon domain',
        'STRINGS: Invoke-BloodHound SharpHound neo4j collectors domain admins\nFLS: Windows/Temp/SharpHound.exe',
        'FLS: Windows/Temp/PowerView.ps1\nSTRINGS: Get-NetUser Get-NetGroup Get-NetDomainController Find-LocalAdminAccess',
        'STRINGS: getdomaingroup getdomainuser localgroup net accounts domain\nPREFETCH: POWERSHELL.EXE-HASH.pf',
    ],
    'T1059.001': [
        'FLS: AppData/Roaming/Microsoft/Windows/payload.ps1\nSTRINGS: Invoke-Expression IEX FromBase64String download',
        'STRINGS: powershell -nop -w hidden -enc SQBFAFgAIA cradle\nPREFETCH: POWERSHELL.EXE-HASH.pf',
        'FLS: Windows/Prefetch/POWERSHELL.EXE-HASH.pf\nSTRINGS: bypass noprofile encodedcommand hidden',
        'STRINGS: System.Net.WebClient DownloadString Invoke-Expression cradle hidden window\nFLS: Temp/stage1.ps1',
        'STRINGS: FromBase64String Invoke-Expression iex download execute payload\nFLS: Users/Public/run.ps1',
        'FLS: AppData/Local/Microsoft/Windows/PowerShell/ConsoleHost_history.txt\nSTRINGS: powershell -nop -w hidden -enc IEX',
        'STRINGS: wscript.exe cscript.exe vbs powershell launcher dropper script\nFLS: Windows/Temp/launcher.vbs',
        'STRINGS: Add-Type Reflection.Assembly LoadWithPartialName AmsiScanBuffer bypass patch\nFLS: Temp/bypass.ps1',
        'FLS: AppData/Local/Temp/tmp.ps1\nSTRINGS: invoke-expression download execute payload hidden window noprofile',
        'STRINGS: powershell -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand\nFLS: Temp/run.ps1',
    ],
    'T1548.002': [
        'STRINGS: fodhelper.exe ms-settings shell open command UAC bypass elevation\nREG SET: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command = cmd.exe',
        'REG SET: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command = cmd.exe\nSTRINGS: fodhelper UAC bypass high integrity',
        'STRINGS: sdclt.exe /kickoffelev Control_RunDLL ShellExecute bypass\nREG SET: HKCU\\Software\\Classes\\Folder\\shell\\open\\command = payload.exe',
        'REG SET: HKCU\\Software\\Classes\\mscfile\\shell\\open\\command = payload.exe\nSTRINGS: eventvwr mmc UAC bypass elevation',
        'FLS: Windows/Prefetch/FODHELPER.EXE-HASH.pf\nREG SET: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command = C:\\Windows\\Temp\\payload.exe',
        'STRINGS: ComputerDefaults.exe SecurityCenter.exe UAC bypass high integrity HKCU classes\nREG SET: Software\\Classes',
        'REG SET: HKCU\\Software\\Classes\\exefile\\shell\\open\\command = payload.exe\nSTRINGS: UAC bypass fileless registry elevation',
        'STRINGS: eventvwr.exe mmc.exe bypass IntegrityLevel High elevation auto-elevate\nFLS: Windows/Temp/uac_bypass.exe',
        'REG SET: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command = C:\\Users\\Public\\payload.exe\nSTRINGS: fodhelper bypass',
        'STRINGS: icacls.exe bypass integritylevel auto-elevate fodhelper sdclt elevation\nPREFETCH: SDCLT.EXE-HASH.pf',
    ],
    'T1560.001': [
        'FLS: Windows/Temp/system.rar Windows/Temp/rar.exe\nSTRINGS: WinRAR command line rar archive password compress',
        'STRINGS: 7za.exe a -p password -mhe archive.7z encrypt headers\nFLS: Documents/data.7z',
        'FLS: Users/username/Desktop/docs.rar\nSTRINGS: WinRAR Registered archive password protected headers',
        'STRINGS: compact /EXE:LZX /S files collected archive exfil compress\nFLS: Windows/Temp/collected.cab',
        'FLS: Windows/Temp/rar.exe Windows/Temp/data.rar\nSTRINGS: WinRAR -hp password headers encrypted',
        'STRINGS: 7z.exe a -t7z -p -r collected.7z target directory\nFLS: Windows/Temp/collected.7z Windows/Temp/7z.exe',
        'FLS: Users/user/AppData/Local/Temp/backup.rar\nSTRINGS: WinRAR add archive password compression level',
        'STRINGS: Compress-Archive zip powershell archive exfiltration output path\nFLS: Windows/Temp/output.zip',
        'FLS: Windows/Temp/audiocapture.rar Windows/Temp/msf_rec.dll\nSTRINGS: record audio microphone capture rar archive',
        'STRINGS: pkzip winzip wrar rar.exe compress collect exfil archive password\nFLS: Windows/Temp/exfil.zip',
    ],
}

# ---------------------------------------------------------------------------
# Benign SIFT-format artifacts — real Windows artifacts that look suspicious
# but are legitimate.  30% of training events come from here.
# ---------------------------------------------------------------------------
_BENIGN: list[str] = [
    'FLS: Windows/System32/svchost.exe (size 30208)\nSTRINGS: Microsoft Corporation Microsoft Windows Operating System',
    'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive = C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe',
    'FLS: Windows/Prefetch/CHROME.EXE-HASH.pf\nSTRINGS: Google Chrome Google LLC',
    'FLS: Windows/System32/drivers/mrt.sys\nSTRINGS: Microsoft Malicious Software Removal Tool driver',
    'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdge = C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'FLS: Windows/System32/WindowsPowerShell/v1.0/powershell.exe (size 449536)\nSTRINGS: Microsoft Corporation Windows PowerShell legitimate signed',
    'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit = C:\\Windows\\system32\\userinit.exe,\nSTRINGS: userinit.exe legitimate',
    'FLS: Windows/SysWOW64/winrm.vbs\nSTRINGS: Windows Remote Management legitimate Microsoft script',
    'STRINGS: Microsoft Corporation All rights reserved MSVCP140.dll Version=6.1.7601 signed\nFLS: Windows/System32/msvcp140.dll',
    'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\nSTRINGS: Windows Update scheduled task legitimate',
    'FLS: Windows/System32/lsass.exe (size 30208)\nSTRINGS: Microsoft Corporation Local Security Authority Process signed',
    'REG: HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\ImagePath = C:\\Program Files\\Windows Defender\\MsMpEng.exe',
    'FLS: Users/user/AppData/Local/Microsoft/Windows/INetCache/IE\nSTRINGS: Internet Explorer cache legitimate browsing',
    'STRINGS: MicrosoftEdgeUpdate.exe Microsoft signed update service scheduled task\nFLS: Windows/Prefetch/MICROSOFTEDGEUPDATE.EXE-HASH.pf',
    'REG SET: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth = C:\\Windows\\system32\\SecurityHealthSystray.exe',
]


class ForensicRedAgent:
    """
    Red Agent for disk forensic domain ASL training.

    Produces SIFT-format attack artifact strings — the same format that
    blue_agent.py sees when running strings/fls/rip.pl on a mounted image.

    Interface mirrors MordorRedAgent so ForensicBrain can swap it in.
    """

    def __init__(self):
        self.evasions:      dict[str, list] = {}
        self.current_index: int = 0
        self.last_raw_event: str = ''     # last artifact string for grounded learning
        self._datasets:     dict[str, list[str]] = {}
        self._load_enrichment()

    def _load_enrichment(self):
        """Load Hybrid Analysis records from datasets/forensic/ if present."""
        total = 0
        for tid in _SEED:
            path = os.path.join(_FORENSIC_DS, f'{tid}.jsonl')
            if not os.path.exists(path):
                continue
            records = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            rec = json.loads(line)
                            artifact = rec.get('artifact', '')
                            if artifact:
                                records.append(artifact)
                        except json.JSONDecodeError:
                            pass
            if records:
                self._datasets[tid] = records
                total += len(records)
        if total:
            print(f'  📂 Forensic enrichment loaded: {total} HA records')
        else:
            print(f'  🌱 Seed-only mode ({sum(len(v) for v in _SEED.values())} seed artifacts)')
            print(f'     Run forensic_data_agent.py --fetch --all to enrich')

    def next_technique(self, benign_ratio: float = 0.3):
        """
        30% benign SIFT artifacts, 70% attack.
        Returns (technique_id, artifact_string).
        """
        if random.random() < benign_ratio:
            art = random.choice(_BENIGN)
            self.last_raw_event = art
            return 'BENIGN', art

        tids = list(_SEED.keys())
        tid  = tids[self.current_index % len(tids)]
        self.current_index += 1
        return tid, self._pick_artifact(tid)

    def _pick_artifact(self, tid: str) -> str:
        """
        Pick an artifact for tid.
        Priority: evolved evasion (50%), HA enrichment (30%), seed (20%).
        """
        ev = self.evasions.get(tid, [])
        ha = self._datasets.get(tid, [])

        r = random.random()
        if ev and r < 0.50:
            art = random.choice(ev)['modified_artifact']
        elif ha and r < 0.80:
            art = random.choice(ha)
        else:
            art = random.choice(_SEED[tid])

        self.last_raw_event = art
        return art

    def evolve(self, tid: str, caught_by: list):
        """
        Red evolves using Claude when caught.
        Generates disk-level evasion (string fragmentation, ADS, LOTL, etc.)
        rather than Sysmon-level evasion.
        """
        import anthropic

        sample = self._pick_artifact(tid)
        client = anthropic.Anthropic()

        try:
            resp = client.messages.create(
                model='claude-haiku-4-5-20251001',
                max_tokens=250,
                messages=[{
                    'role': 'user',
                    'content': (
                        f'You are a red teamer evading forensic disk analysis.\n'
                        f'Technique: {tid}\n'
                        f'Caught by patterns: {caught_by}\n'
                        f'Original SIFT artifact:\n{sample}\n\n'
                        f'Suggest ONE realistic disk-level evasion. Options:\n'
                        f'  - String fragmentation or encoding (split "{caught_by[0] if caught_by else "mimikatz"}")\n'
                        f'  - Alternate tool (different binary, same objective)\n'
                        f'  - Alternate path/registry location\n'
                        f'  - LOTL (living-off-the-land binary)\n'
                        f'  - Timestamp manipulation / ADS\n\n'
                        f'Respond in JSON only, no markdown:\n'
                        f'{{"modified_artifact": "SIFT-format artifact string", '
                        f'"evasion": "one-line explanation"}}'
                    ),
                }],
            )
            raw   = resp.content[0].text.strip()
            start = raw.find('{')
            end   = raw.rfind('}') + 1
            if start == -1 or end <= start:
                raise ValueError(f'no JSON in: {raw[:80]!r}')
            sug = json.loads(raw[start:end])
            if tid not in self.evasions:
                self.evasions[tid] = []
            self.evasions[tid].append(sug)
            print(f'   🔴 Evolved [{tid}]: {sug["evasion"][:70]}')
            return sug
        except Exception as e:
            print(f'   ⚠️  Red evolve failed: {e}')
            return None

    def cleanup(self, tid: str):
        pass  # no external state to clean up
