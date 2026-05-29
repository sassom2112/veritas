#!/usr/bin/env python3
"""
extract_iocs.py — Extract confirmed IOCs from a completed VERITAS investigation.

Reads the triage report + auditor transcript for a host and writes a structured
IOC JSON file that can be passed to subsequent investigations via --ioc-file.

Usage:
    python3 custom-agent/extract_iocs.py <host>
    python3 custom-agent/extract_iocs.py nromanoff
    python3 custom-agent/extract_iocs.py nfury --reports-dir /path/to/reports

Output: reports/<host>-iocs.json
"""

import argparse
import ipaddress
import json
import os
import re
import sys

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

# Regex patterns for artifact extraction
_IP_RE    = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_FNAME_RE = re.compile(
    r'(?:^|[\s/\\])([A-Za-z0-9_\-]+\.(?:exe|dll|bin|dmp|ps1|vbs|bat|cmd|rar|zip|7z))\b',
    re.IGNORECASE,
)

# Patterns that signal an account name in prose or tool output.
# Anchored tightly to avoid matching prose words like "manipulation", "creation".
_ACCOUNT_PATTERNS = [
    re.compile(r'(?:username|user name|account name)[:\s]+([A-Za-z][A-Za-z0-9_\-.]{2,29})', re.I),
    re.compile(r'(?:Users|Profiles)[/\\]([A-Za-z][A-Za-z0-9_\-.]{2,29})(?:[/\\]|$)', re.I),
    re.compile(r'(?:logged on as|running as)[:\s]+([A-Za-z][A-Za-z0-9_\-.]{2,29})', re.I),
    re.compile(r'RID[:\s]+\d+[^\n]*?Name\s*:\s*([A-Za-z][A-Za-z0-9_\-.]{2,29})', re.I),
]
_ACCOUNT_BORING = frozenset({
    'system', 'administrator', 'admin', 'network', 'local', 'service',
    'domain', 'user', 'account', 'default', 'guest', 'public', 'users',
    'everyone', 'interactive', 'authenticated', 'creator', 'owner',
    # Common prose words that appear near "account" in forensic analysis text
    'manipulation', 'creation', 'manager', 'changes', 'activity', 'type',
    'enabled', 'disabled', 'created', 'changed', 'suggests', 'credentials',
    'for', 'or', 'with', 'which', 'versus', 'the', 'and',
})

# Legitimate Windows system binaries — never IOCs
_BORING_FILENAMES = frozenset({
    'svchost.exe', 'lsass.exe', 'explorer.exe', 'services.exe', 'csrss.exe',
    'winlogon.exe', 'smss.exe', 'wininit.exe', 'spoolsv.exe', 'taskmgr.exe',
    'conhost.exe', 'logonui.exe', 'rundll32.exe', 'regsvr32.exe', 'cmd.exe',
    'powershell.exe', 'msiexec.exe', 'dllhost.exe', 'taskhost.exe',
    'ntoskrnl.exe', 'hal.dll', 'ntdll.dll', 'kernel32.dll', 'user32.dll',
    'advapi32.dll', 'msvcrt.dll', 'shell32.dll', 'ole32.dll', 'rpcrt4.dll',
    # VC++ runtimes (all versions)
    'msvcm90.dll', 'msvcp90.dll', 'msvcr90.dll',
    'msvcm80.dll', 'msvcp80.dll', 'msvcr80.dll',
    # .NET / Python runtimes
    'mscorlib.dll', 'python27.dll', 'python25.dll',
    'pywintypes27.dll', 'pywintypes25.dll',
    # Built-in Windows tools always present on disk
    'reg.exe',
    # McAfee / AV agent binary shipped with many enterprise images
    'mfevtps.exe',
})

# Techniques associated with account discovery / creation
_ACCOUNT_TECHNIQUES = frozenset({'T1087', 'T1087.001', 'T1087.002',
                                  'T1136', 'T1136.001', 'T1078', 'T1078.002'})

# IPs that are never IOCs
_BORING_PREFIXES = ('127.', '0.', '255.', '169.254.', '10.', '192.168.', '172.')


def _is_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _extract_from_text(text: str, iocs: dict) -> None:
    for ip in _IP_RE.findall(text):
        if _is_routable(ip) and ip not in iocs['c2_ips']:
            iocs['c2_ips'].append(ip)

    for m in _FNAME_RE.finditer(text):
        fname = m.group(1).lower()
        if (fname not in iocs['filenames']
                and fname not in _BORING_FILENAMES
                and not any(fname.startswith(p) for p in ('setup', 'install', 'update', 'msi'))):
            iocs['filenames'].append(fname)


def _extract_accounts_from_text(text: str, iocs: dict) -> None:
    """Extract account names from investigation prose or tool output."""
    for pat in _ACCOUNT_PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1).strip()
            if (name.lower() not in _ACCOUNT_BORING
                    and len(name) >= 2
                    and name not in iocs['accounts']):
                iocs['accounts'].append(name)


def extract_iocs(host: str, reports_dir: str) -> dict:
    """
    Build an IOC dict from a completed investigation.
    CONFIRMED findings are extracted as definite IOCs.
    INCONCLUSIVE findings from account/C2 techniques are extracted as candidates
    (tagged tier='candidate') so campaign mode still propagates them.
    """
    iocs: dict = {
        'source_host':   host,
        'c2_ips':        [],
        'filenames':     [],
        'accounts':      [],
        'registry_keys': [],
        'directories':   [],
    }

    triage_path = os.path.join(reports_dir, f'{host}-custom-agent-report.json')
    audit_path  = os.path.join(reports_dir, f'{host}-auditor-transcript.json')
    memory_path = os.path.join(reports_dir, f'{host}-memory-triage-report.json')

    if not os.path.exists(triage_path):
        print(f"  ERROR: triage report not found: {triage_path}")
        return iocs

    with open(triage_path) as f:
        triage = json.load(f)

    confirmed_ids:    set[str] = set()
    inconclusive_ids: set[str] = set()

    if os.path.exists(audit_path):
        with open(audit_path) as f:
            audit = json.load(f)

        for e in audit.get('transcript', []):
            verdict = e.get('final_verdict')
            tid     = e.get('finding_id', '')
            if verdict == 'CONFIRMED':
                confirmed_ids.add(tid)
            elif verdict == 'INCONCLUSIVE':
                inconclusive_ids.add(tid)

        # Mine tool output from all auditor challenges (confirmed + inconclusive)
        for entry in audit.get('transcript', []):
            verdict = entry.get('final_verdict')
            for ch in entry.get('challenges', []):
                # 'tool_output' is the correct field name in the transcript
                text = ch.get('tool_output', '') + ' ' + ch.get('reasoning', '')
                if verdict == 'CONFIRMED':
                    _extract_from_text(text, iocs)
                    _extract_accounts_from_text(text, iocs)
                elif verdict == 'INCONCLUSIVE':
                    # Still harvest IPs and accounts as candidates
                    _extract_from_text(text, iocs)
                    _extract_accounts_from_text(text, iocs)
    else:
        confirmed_ids = set(triage.get('techniques_detected', []))

    matched = triage.get('matched_signals', {})

    # Confirmed signals → definite IOCs
    _REG_RE = re.compile(r'^HK(?:LM|CU|U|CR|CC)[\\]', re.I)
    for tid in confirmed_ids:
        for sig in matched.get(tid, []):
            if re.match(r'\d+\.\d+\.\d+\.\d+', sig) and _is_routable(sig):
                if sig not in iocs['c2_ips']:
                    iocs['c2_ips'].append(sig)
            elif re.search(r'\.(?:exe|dll|bin|dmp|ps1)$', sig, re.I):
                fname = os.path.basename(sig).lower()
                if fname not in _BORING_FILENAMES and fname not in iocs['filenames']:
                    iocs['filenames'].append(fname)
            elif _REG_RE.match(sig) and sig not in iocs['registry_keys']:
                iocs['registry_keys'].append(sig)

    # Inconclusive signals for account/C2 techniques → candidate IOCs
    # (vibranium in T1087.001 inconclusive, C2 IP in T1071.001 inconclusive, etc.)
    for tid in inconclusive_ids:
        for sig in matched.get(tid, []):
            if tid in _ACCOUNT_TECHNIQUES:
                # Simple alphanumeric signal in an account technique = likely username
                if (re.match(r'^[A-Za-z][A-Za-z0-9_\-.]{1,29}$', sig)
                        and sig.lower() not in _ACCOUNT_BORING
                        and sig not in iocs['accounts']):
                    iocs['accounts'].append(sig)
            if re.match(r'\d+\.\d+\.\d+\.\d+', sig) and _is_routable(sig):
                if sig not in iocs['c2_ips']:
                    iocs['c2_ips'].append(sig)

    # Prose analysis — IPs, filenames, and account names mentioned by the agent
    analysis = triage.get('claude_analysis', '')
    _extract_from_text(analysis, iocs)
    _extract_accounts_from_text(analysis, iocs)

    # Memory triage report — same harvest on memory analysis prose
    if os.path.exists(memory_path):
        with open(memory_path) as f:
            mem = json.load(f)
        mem_text = mem.get('memory_analysis', '')
        _extract_from_text(mem_text, iocs)
        _extract_accounts_from_text(mem_text, iocs)
        # Memory matched signals
        for tid, sigs in mem.get('matched_signals', {}).items():
            for sig in sigs:
                if re.match(r'\d+\.\d+\.\d+\.\d+', sig) and _is_routable(sig):
                    if sig not in iocs['c2_ips']:
                        iocs['c2_ips'].append(sig)

    # Deduplicate and sort
    for key in ('c2_ips', 'filenames', 'registry_keys', 'directories', 'accounts'):
        iocs[key] = sorted(set(iocs[key]))

    return iocs


def merge_iocs(*ioc_files: str) -> dict:
    """Merge multiple IOC files into one, deduplicating all lists."""
    merged: dict = {
        'source_hosts':  [],
        'c2_ips':        [],
        'filenames':     [],
        'accounts':      [],
        'registry_keys': [],
        'directories':   [],
    }
    for path in ioc_files:
        with open(path) as f:
            data = json.load(f)
        host = data.get('source_host') or data.get('source_hosts', [])
        if isinstance(host, str):
            merged['source_hosts'].append(host)
        elif isinstance(host, list):
            merged['source_hosts'].extend(host)
        for key in ('c2_ips', 'filenames', 'accounts', 'registry_keys', 'directories'):
            merged[key].extend(data.get(key, []))

    for key in ('c2_ips', 'filenames', 'accounts', 'registry_keys', 'directories'):
        merged[key] = sorted(set(merged[key]))
    merged['source_hosts'] = sorted(set(merged['source_hosts']))
    return merged


def main():
    parser = argparse.ArgumentParser(
        description='Extract confirmed IOCs from a completed VERITAS investigation'
    )
    parser.add_argument('host', help='Host name (e.g. nromanoff, nfury)')
    parser.add_argument('--reports-dir', default=_REPORTS,
                        help='Reports directory (default: ../reports)')
    parser.add_argument('--merge', nargs='+', metavar='IOC_FILE',
                        help='Merge these IOC files together instead of extracting')
    parser.add_argument('--output', '-o', metavar='PATH',
                        help='Output path (default: reports/<host>-iocs.json)')
    args = parser.parse_args()

    if args.merge:
        missing = [f for f in args.merge if not os.path.exists(f)]
        if missing:
            print(f"ERROR: files not found: {missing}")
            sys.exit(1)
        result = merge_iocs(*args.merge)
        out = args.output or os.path.join(args.reports_dir, f'{args.host}-campaign-iocs.json')
    else:
        result = extract_iocs(args.host, args.reports_dir)
        out = args.output or os.path.join(args.reports_dir, f'{args.host}-iocs.json')

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"IOC file written: {out}")
    print(f"  C2 IPs:        {result['c2_ips']}")
    print(f"  Filenames:     {result['filenames']}")
    print(f"  Accounts:      {result['accounts']}")
    print(f"  Registry keys: {result['registry_keys']}")
    print(f"  Directories:   {result['directories']}")


if __name__ == '__main__':
    main()
