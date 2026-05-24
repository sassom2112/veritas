#!/usr/bin/env python3
"""
forensic_data_agent.py — Malware sample data pipeline for forensic ASL training.

Two-stage fetch:
  Stage 1 — MalwareBazaar (free, no key): query by malware family/tag → SHA256 list
  Stage 2 — Hybrid Analysis (optional, needs API key): report/{sha256}/summary → strings,
            dropped files, registry modifications (full sandbox behavior)

If no HA key is set, stage 2 is skipped and MB metadata alone is used.
The seed data in forensic_red_agent.py covers behavioral signals (registry, file paths);
this agent adds real file-name diversity from actual malware samples in the wild.

Usage:
    python3 custom-agent/forensic_data_agent.py --stats
    python3 custom-agent/forensic_data_agent.py --fetch --all
    python3 custom-agent/forensic_data_agent.py --fetch --technique T1003.001
    python3 custom-agent/forensic_data_agent.py --test-ha     # check if HA report endpoint works
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

_HERE         = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, '..'))
_FORENSIC_DS  = os.path.join(_PROJECT_ROOT, 'datasets', 'forensic')
_CACHE_DIR    = os.path.join(_FORENSIC_DS, '.cache')

MB_BASE  = 'https://mb-api.abuse.ch/api/v1/'
HA_BASE  = 'https://www.hybrid-analysis.com/api/v2'
_HA_INTERVAL = 0.4   # 150 req/min (quota: 200/min)
_MB_INTERVAL = 1.5   # MalwareBazaar asks for polite rate limiting

# ---------------------------------------------------------------------------
# Technique → malware families / tags known to exhibit this technique.
# Used to query MalwareBazaar for real sample SHA256s.
# signal_strings: technique-invariant strings for SIFT format construction
#   when HA report is unavailable.
# ---------------------------------------------------------------------------
TECHNIQUE_SEARCHES = {
    'T1003.001': {
        'name': 'LSASS Memory Dumping',
        'mb_families': ['Mimikatz', 'LaZagne', 'WCE', 'Invoke-Mimikatz'],
        'mb_tags':     ['credential-dumping', 'lsass', 'mimikatz'],
        'signal_strings': ['mimikatz', 'sekurlsa', 'lsass.dmp', 'procdump', 'wdigest'],
    },
    'T1547.001': {
        'name': 'Registry Run Key Persistence',
        'mb_families': ['AsyncRAT', 'AgentTesla', 'QuasarRAT', 'Remcos', 'NjRAT'],
        'mb_tags':     ['persistence'],
        'signal_strings': ['currentversion\\run', 'currentversion\\runonce', 'dllhost\\svchost'],
    },
    'T1569.002': {
        'name': 'PsExec Service Execution',
        'mb_families': ['PsExec', 'Cobalt Strike'],
        'mb_tags':     ['psexec', 'lateral-movement'],
        'signal_strings': ['psexesvc', 'psexec', 'remcomsvc', 'admin$', 'svcctl'],
    },
    'T1036.005': {
        'name': 'Binary Masquerading',
        'mb_families': ['Gh0stRAT', 'NanoCore', 'Netwire'],
        'mb_tags':     ['masquerading', 'dropper'],
        'signal_strings': ['svchost', 'dllhost', 'wrong path', 'wrong version'],
    },
    'T1087.001': {
        'name': 'Account Discovery',
        'mb_families': ['SharpHound', 'BloodHound', 'Seatbelt', 'ADRecon'],
        'mb_tags':     ['discovery', 'enumeration'],
        'signal_strings': ['seatbelt', 'sharphound', 'bloodhound', 'enumdomainusers', 'getdomainuser'],
    },
    'T1059.001': {
        'name': 'PowerShell Execution',
        'mb_families': ['PowerShell', 'AgentTesla', 'Emotet'],
        'mb_tags':     ['powershell', 'dropper', 'downloader'],
        'signal_strings': ['invoke-expression', 'frombase64string', 'powershell -enc', 'iex'],
    },
    'T1548.002': {
        'name': 'UAC Bypass',
        'mb_families': ['Cobalt Strike', 'Meterpreter', 'UACMe'],
        'mb_tags':     ['uac-bypass', 'privilege-escalation'],
        'signal_strings': ['fodhelper', 'sdclt', 'eventvwr', 'ms-settings'],
    },
    'T1560.001': {
        'name': 'Data Archival',
        'mb_families': ['WinRAR', 'RAR'],
        'mb_tags':     ['archive', 'collection', 'exfiltration'],
        'signal_strings': ['winrar', 'rar.exe', '7za.exe', '.rar', 'compress'],
    },
}


# ---------------------------------------------------------------------------
# MalwareBazaar client (no API key required)
# ---------------------------------------------------------------------------

_mb_last   = 0.0
_mb_api_key = ''   # set via MALWAREBAZAAR_API_KEY env var


def _mb_post(body: dict) -> dict:
    global _mb_last
    elapsed = time.time() - _mb_last
    if elapsed < _MB_INTERVAL:
        time.sleep(_MB_INTERVAL - elapsed)
    _mb_last = time.time()

    data    = urllib.parse.urlencode(body).encode()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent':   'ADVERSA-forensic-trainer/1.0',
    }
    if _mb_api_key:
        headers['Auth-Key'] = _mb_api_key

    req = urllib.request.Request(MB_BASE, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f'    MB API error: {e}')
        return {}


def mb_by_family(family: str, limit: int = 100) -> list:
    result = _mb_post({'query': 'get_siginfo', 'signature': family, 'limit': limit})
    return result.get('data') or []


def mb_by_tag(tag: str, limit: int = 100) -> list:
    result = _mb_post({'query': 'get_taginfo', 'tag': tag, 'limit': limit})
    return result.get('data') or []


# ---------------------------------------------------------------------------
# Hybrid Analysis client (optional — API key needed for reports)
# ---------------------------------------------------------------------------

_ha_last = 0.0

def _ha_get(endpoint: str, api_key: str) -> dict:
    global _ha_last
    elapsed = time.time() - _ha_last
    if elapsed < _HA_INTERVAL:
        time.sleep(_HA_INTERVAL - elapsed)
    _ha_last = time.time()

    url = f'{HA_BASE}/{endpoint}'
    req = urllib.request.Request(url, headers={
        'api-key':    api_key,
        'User-Agent': 'Falcon Sandbox',
        'Accept':     'application/json',
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        return {'_error': str(e)}


def ha_report(sha256: str, api_key: str) -> dict:
    """Fetch full HA sandbox report for a SHA256 (uses report cache)."""
    cache_path = os.path.join(_CACHE_DIR, f'{sha256}.json')
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            return json.load(f)

    report = _ha_get(f'report/{sha256}/summary', api_key)
    if report and '_error' not in report:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(report, f)
    return report


def test_ha(api_key: str) -> bool:
    """Test whether HA report endpoint is reachable with this key."""
    # Use a well-known public SHA256 (EICAR test file — always in HA)
    eicar_sha256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    print(f'  Testing HA report endpoint with EICAR SHA256...')
    r = _ha_get(f'report/{eicar_sha256}/summary', api_key)
    if '_error' in r:
        print(f'  HA report FAILED: {r["_error"]}')
        return False
    print(f'  HA report OK — verdict: {r.get("verdict", "unknown")}')
    return True


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def _coerce_list(val) -> list:
    if isinstance(val, list):  return val
    if isinstance(val, str):   return [val]
    return []


def normalize_ha_report(report: dict, technique_id: str) -> dict | None:
    """Full HA sandbox report → SIFT-format artifact."""
    strings_raw = (report.get('strings')
                   or report.get('extracted_strings')
                   or [])
    dropped  = _coerce_list(report.get('dropped_files', []))
    registry = _coerce_list(report.get('registry', []))
    domains  = _coerce_list(report.get('domains', []))
    hosts    = _coerce_list(report.get('hosts', []))
    tags     = _coerce_list(report.get('classification_tags', []))

    if not (strings_raw or dropped or registry):
        return None

    parts = []

    usable = [s for s in strings_raw
              if isinstance(s, str) and 4 <= len(s) <= 120
              and any(c.isalpha() for c in s)
              and not s.startswith('http')]
    if usable:
        parts.append('STRINGS: ' + ' | '.join(usable[:25]))

    for f in dropped[:10]:
        name = f.get('name') or f.get('filename') or ''
        sha  = f.get('sha256') or f.get('md5') or ''
        if name:
            parts.append(f'FLS: {name} sha256={sha[:12]}')

    for reg in registry[:8]:
        key = reg.get('key') or reg.get('registry_key') or ''
        val = reg.get('value') or reg.get('data') or ''
        op  = (reg.get('operation') or reg.get('type') or 'set').upper()
        if key:
            parts.append(f'REG {op}: {key} = {str(val)[:80]}')

    if domains or hosts:
        parts.append('NETWORK: ' + ' '.join(str(h) for h in (domains + hosts)[:5]))
    if tags:
        parts.append('TAGS: ' + ' '.join(str(t) for t in tags[:6]))

    if len(parts) < 2:
        return None

    return {
        'technique_id': technique_id,
        'sha256':       report.get('sha256', ''),
        'artifact':     '\n'.join(parts),
        'source':       'ha_report',
        'fetched_at':   datetime.now(timezone.utc).isoformat(),
    }


def normalize_mb_metadata(sample: dict, technique_id: str,
                           signal_strings: list) -> dict | None:
    """
    MalwareBazaar sample metadata → SIFT-format artifact.
    Used when HA report is unavailable.  Combines real file names from MB
    with technique-invariant signal strings to produce a realistic example.
    """
    fname  = sample.get('file_name', '')
    fsize  = sample.get('file_size', 0)
    sig    = sample.get('signature', '')
    tags   = [t for t in _coerce_list(sample.get('tags'))
              if len(t) > 2 and not t.startswith('T1')]

    if not fname and not sig:
        return None

    parts = []

    if fname:
        parts.append(f'FLS: {fname} (size {fsize})')

    # Build STRINGS line: technique signals + family name + sample-specific tags
    family_tokens = ([sig.lower()] if sig else []) + [t.lower() for t in tags[:3]]
    # Rotate through signal_strings so different samples emphasize different signals
    sig_subset = signal_strings[:5]
    all_tokens = list(dict.fromkeys(sig_subset + family_tokens))
    if all_tokens:
        parts.append('STRINGS: ' + ' | '.join(all_tokens))

    if sig:
        parts.append(f'FAMILY: {sig}')

    return {
        'technique_id': technique_id,
        'sha256':       sample.get('sha256_hash', ''),
        'artifact':     '\n'.join(parts),
        'source':       'mb_metadata',
        'fetched_at':   datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Fetch pipeline
# ---------------------------------------------------------------------------

def fetch_technique(tid: str, config: dict, max_samples: int,
                    api_key: str = '') -> list:
    print(f'\n  {tid} — {config["name"]}')
    seen:    set  = set()
    samples: list = []

    # Stage 1: collect SHA256s from MalwareBazaar
    for family in config['mb_families']:
        if len(samples) >= max_samples:
            break
        print(f'    MB family: {family}', end='', flush=True)
        hits = mb_by_family(family, limit=max_samples * 2)
        new  = [h for h in hits if h.get('sha256_hash') not in seen]
        samples.extend(new[:max_samples - len(samples)])
        for h in new:
            seen.add(h.get('sha256_hash', ''))
        print(f' → {len(new)} samples')

    for tag in config['mb_tags']:
        if len(samples) >= max_samples:
            break
        print(f'    MB tag: {tag}', end='', flush=True)
        hits = mb_by_tag(tag, limit=max_samples * 2)
        new  = [h for h in hits if h.get('sha256_hash') not in seen]
        samples.extend(new[:max_samples - len(samples)])
        for h in new:
            seen.add(h.get('sha256_hash', ''))
        print(f' → {len(new)} samples')

    if not samples:
        print('    No MB samples found')
        return []

    print(f'    {len(samples)} unique samples — enriching...')

    # Stage 2: try HA report per SHA256 (if API key provided)
    records: list = []
    for s in samples[:max_samples]:
        sha = s.get('sha256_hash', '')
        if not sha:
            continue

        rec = None
        if api_key:
            report = ha_report(sha, api_key)
            if report and '_error' not in report and 'sha256' in report:
                rec = normalize_ha_report(report, tid)
                if rec:
                    print(f'    {sha[:14]} HA ✅')

        if rec is None:
            # Fall back to MB metadata only
            rec = normalize_mb_metadata(s, tid, config['signal_strings'])
            if rec:
                print(f'    {sha[:14]} MB-only')

        if rec:
            records.append(rec)

    return records


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def save_records(tid: str, records: list) -> str:
    os.makedirs(_FORENSIC_DS, exist_ok=True)
    path = os.path.join(_FORENSIC_DS, f'{tid}.jsonl')
    mode = 'a' if os.path.exists(path) else 'w'
    with open(path, mode) as f:
        for rec in records:
            f.write(json.dumps(rec) + '\n')
    return path


def load_records(tid: str) -> list:
    path = os.path.join(_FORENSIC_DS, f'{tid}.jsonl')
    if not os.path.exists(path):
        return []
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def print_stats():
    print('\nForensic Dataset Statistics')
    print('=' * 56)
    total, ha_n, mb_n = 0, 0, 0
    for tid, cfg in TECHNIQUE_SEARCHES.items():
        recs  = load_records(tid)
        n     = len(recs)
        total += n
        ha_n  += sum(1 for r in recs if r.get('source') == 'ha_report')
        mb_n  += sum(1 for r in recs if r.get('source') == 'mb_metadata')
        icon  = '✅' if n >= 10 else ('⚠️ ' if n > 0 else '❌')
        print(f'  {icon} {tid}: {n:3d} records  ({cfg["name"]})')
    cached = len(os.listdir(_CACHE_DIR)) if os.path.isdir(_CACHE_DIR) else 0
    print(f'\n  Total: {total} records  '
          f'(HA full reports: {ha_n}  MB metadata: {mb_n})')
    print(f'  HA cache: {cached} SHA256 reports')
    if total == 0:
        print('\n  Run: python3 custom-agent/forensic_data_agent.py --fetch --all')
        print('  Training works without this — seed data in forensic_red_agent.py')
        print('  is sufficient to start. This enriches with real sample diversity.')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Malware sample pipeline for forensic ASL training'
    )
    parser.add_argument('--fetch',       action='store_true')
    parser.add_argument('--all',         action='store_true',
                        help='Fetch all techniques')
    parser.add_argument('--technique',   metavar='TID')
    parser.add_argument('--max-samples', type=int, default=20)
    parser.add_argument('--stats',       action='store_true')
    parser.add_argument('--test-ha',     action='store_true',
                        help='Test whether HA report endpoint works with your key')
    args = parser.parse_args()

    global _mb_api_key
    _mb_api_key = os.environ.get('MALWAREBAZAAR_API_KEY', '')
    api_key     = os.environ.get('HYBRID_ANALYSIS_API_KEY', '')

    if _mb_api_key:
        print(f'MalwareBazaar: authenticated (Auth-Key set)')
    else:
        print(f'MalwareBazaar: unauthenticated (set MALWAREBAZAAR_API_KEY for higher limits)')

    if args.test_ha:
        if not api_key:
            print('Set HYBRID_ANALYSIS_API_KEY first')
            sys.exit(1)
        ok = test_ha(api_key)
        sys.exit(0 if ok else 1)

    if args.stats or not args.fetch:
        print_stats()
        return

    if args.all:
        techniques = list(TECHNIQUE_SEARCHES.keys())
    elif args.technique:
        if args.technique not in TECHNIQUE_SEARCHES:
            print(f'ERROR: Unknown technique {args.technique}')
            print(f'  Valid: {list(TECHNIQUE_SEARCHES.keys())}')
            sys.exit(1)
        techniques = [args.technique]
    else:
        print('Specify --all or --technique TID with --fetch')
        sys.exit(1)

    if api_key:
        print(f'HA key set — will attempt full sandbox reports per SHA256')
        print(f'Running --test-ha first...')
        ha_ok = test_ha(api_key)
        if not ha_ok:
            print('HA report endpoint unreachable — falling back to MB metadata only')
            api_key = ''
    else:
        print('No HYBRID_ANALYSIS_API_KEY — using MalwareBazaar metadata only')

    print(f'\nFetching {len(techniques)} technique(s) — {args.max_samples} samples max each')

    for tid in techniques:
        records = fetch_technique(tid, TECHNIQUE_SEARCHES[tid], args.max_samples, api_key)
        if records:
            path = save_records(tid, records)
            print(f'  → {len(records)} records saved: {os.path.relpath(path)}')
        else:
            print(f'  → No records for {tid}')

    print()
    print_stats()


if __name__ == '__main__':
    main()
