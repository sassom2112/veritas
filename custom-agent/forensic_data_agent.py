#!/usr/bin/env python3
"""
forensic_data_agent.py — Hybrid Analysis API data pipeline.

Downloads sandbox reports keyed by MITRE technique and normalizes them to
SIFT-equivalent forensic artifact descriptions for forensic_brain.py training.

Free tier: 50 requests/day, 5/min. Register at hybrid-analysis.com.
Set HYBRID_ANALYSIS_API_KEY env var before running.

Usage:
    python3 custom-agent/forensic_data_agent.py --stats
    python3 custom-agent/forensic_data_agent.py --fetch --technique T1003.001
    python3 custom-agent/forensic_data_agent.py --fetch --all
    python3 custom-agent/forensic_data_agent.py --fetch --all --max-samples 10
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

_HERE         = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, '..'))
_FORENSIC_DS  = os.path.join(_PROJECT_ROOT, 'datasets', 'forensic')
_CACHE_DIR    = os.path.join(_FORENSIC_DS, '.cache')

HA_BASE       = 'https://www.hybrid-analysis.com/api/v2'
_MIN_INTERVAL = 13.0   # 5 req/min free tier → 12s + 1s buffer

# MITRE technique → Hybrid Analysis search configuration
TECHNIQUE_SEARCHES = {
    'T1003.001': {
        'name': 'LSASS Memory Dumping',
        'terms': ['mimikatz', 'sekurlsa', 'lsass dump', 'procdump lsass'],
    },
    'T1547.001': {
        'name': 'Registry Run Key Persistence',
        'terms': ['currentversion run persistence registry', 'run key malware'],
    },
    'T1569.002': {
        'name': 'PsExec Service Execution',
        'terms': ['psexec psexesvc', 'psexesvc lateral movement'],
    },
    'T1036.005': {
        'name': 'Binary Masquerading',
        'terms': ['masquerading svchost fake', 'binary rename system32'],
    },
    'T1087.001': {
        'name': 'Account Discovery',
        'terms': ['seatbelt enumdomainusers', 'sharpview getdomainuser bloodhound'],
    },
    'T1059.001': {
        'name': 'PowerShell Execution',
        'terms': ['powershell invoke-expression base64', 'powershell -enc iex cradle'],
    },
    'T1548.002': {
        'name': 'UAC Bypass',
        'terms': ['fodhelper uac bypass', 'sdclt eventvwr uac elevation'],
    },
    'T1560.001': {
        'name': 'Data Archival',
        'terms': ['winrar archive exfiltration password', '7zip compress collect exfil'],
    },
}


class HybridAnalysisClient:
    """Thin wrapper around Hybrid Analysis API v2 with rate limiting and SHA256 caching."""

    def __init__(self, api_key: str):
        self.api_key    = api_key
        self._last_req  = 0.0
        os.makedirs(_CACHE_DIR, exist_ok=True)

    def _gate(self):
        elapsed = time.time() - self._last_req
        if elapsed < _MIN_INTERVAL:
            time.sleep(_MIN_INTERVAL - elapsed)
        self._last_req = time.time()

    def _request(self, method: str, endpoint: str,
                 data: dict = None, params: dict = None) -> dict:
        import urllib.request
        import urllib.parse

        self._gate()
        url = f'{HA_BASE}/{endpoint}'
        if params:
            url += '?' + urllib.parse.urlencode(params)

        headers = {
            'api-key':    self.api_key,
            'User-Agent': 'ADVERSA-forensic-trainer/1.0',
            'Accept':     'application/json',
        }
        body = None
        if data:
            body = urllib.parse.urlencode(data).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            print(f"    API {method} /{endpoint}: {e}")
            return {}

    def _cached_summary(self, sha256: str) -> dict | None:
        path = os.path.join(_CACHE_DIR, f'{sha256}.json')
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None

    def _cache_summary(self, sha256: str, data: dict):
        with open(os.path.join(_CACHE_DIR, f'{sha256}.json'), 'w') as f:
            json.dump(data, f)

    def search(self, term: str, count: int = 20) -> list:
        result = self._request('POST', 'search/terms', {
            'term': term, 'verdict': 'malicious', 'count': min(count, 20),
        })
        return result.get('results', [])

    def summary(self, sha256: str) -> dict:
        cached = self._cached_summary(sha256)
        if cached is not None:
            return cached
        data = self._request('GET', f'report/{sha256}/summary')
        if data:
            self._cache_summary(sha256, data)
        return data


def _coerce_list(val) -> list:
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        return [val]
    return []


def normalize_report(report: dict, technique_id: str) -> dict | None:
    """
    Convert a Hybrid Analysis report dict to a SIFT-format artifact description.
    Returns None when the report has too little forensic content to be useful.
    """
    # HA API uses several different field names across versions
    strings_raw = (report.get('strings')
                   or report.get('extracted_strings')
                   or report.get('string_hashes')
                   or [])
    dropped     = _coerce_list(report.get('dropped_files', []))
    registry    = _coerce_list(report.get('registry', []))
    domains     = _coerce_list(report.get('domains', []))
    hosts       = _coerce_list(report.get('hosts', []))
    tags        = _coerce_list(report.get('classification_tags', []))

    if not (strings_raw or dropped or registry):
        return None

    parts = []

    # Strings output — filter to forensically meaningful tokens
    usable = [
        s for s in strings_raw
        if isinstance(s, str)
        and 4 <= len(s) <= 120
        and any(c.isalpha() for c in s)
        and not s.startswith('http')   # URLs are noise for string matching
    ]
    if usable:
        parts.append('STRINGS: ' + ' | '.join(usable[:25]))

    # fls-format dropped files
    for f in dropped[:12]:
        name = f.get('name') or f.get('filename') or ''
        sha  = f.get('sha256') or f.get('md5') or ''
        if name:
            parts.append(f'FLS: {name} sha256={sha[:12]}')

    # rip.pl-format registry modifications
    for reg in registry[:10]:
        key = reg.get('key') or reg.get('registry_key') or ''
        val = reg.get('value') or reg.get('data') or ''
        op  = (reg.get('operation') or reg.get('type') or 'set').upper()
        if key:
            parts.append(f'REG {op}: {key} = {str(val)[:80]}')

    # Network indicators
    if domains or hosts:
        net = ' '.join(str(h) for h in (domains + hosts)[:6])
        parts.append(f'NETWORK: {net}')

    # Classification tags
    if tags:
        parts.append('TAGS: ' + ' '.join(str(t) for t in tags[:8]))

    if len(parts) < 2:
        return None

    return {
        'technique_id': technique_id,
        'sha256':       report.get('sha256', ''),
        'verdict':      report.get('verdict', 'malicious'),
        'artifact':     '\n'.join(parts),
        'source':       'hybrid_analysis',
        'fetched_at':   datetime.now(timezone.utc).isoformat(),
    }


def fetch_technique(client: HybridAnalysisClient, tid: str,
                    config: dict, max_samples: int) -> list:
    """Fetch and normalize up to max_samples reports for one technique."""
    print(f"\n  {tid} — {config['name']}")
    collected: list  = []
    seen_sha256: set = set()

    # Try each search term until we reach max_samples
    for term in config['terms']:
        if len(collected) >= max_samples:
            break
        print(f"    search: '{term}'")
        results = client.search(term, max_samples)
        for result in results:
            if len(collected) >= max_samples:
                break
            sha = result.get('sha256', '')
            if not sha or sha in seen_sha256:
                continue
            seen_sha256.add(sha)

            print(f"    {sha[:14]}...", end='', flush=True)
            rpt  = client.summary(sha)
            if not rpt:
                print(' EMPTY')
                continue
            rec = normalize_report({**result, **rpt}, tid)
            if rec:
                collected.append(rec)
                print(f' OK  ({len(collected)}/{max_samples})')
            else:
                print(' SPARSE')

    return collected


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
    print("\nForensic Dataset Statistics")
    print('=' * 52)
    total = 0
    for tid, cfg in TECHNIQUE_SEARCHES.items():
        n = len(load_records(tid))
        total += n
        icon = '✅' if n >= 10 else ('⚠️ ' if n > 0 else '❌')
        print(f"  {icon} {tid}: {n:3d} records  ({cfg['name']})")
    print(f"\n  Total: {total} forensic artifact records")
    cached = len(os.listdir(_CACHE_DIR)) if os.path.isdir(_CACHE_DIR) else 0
    print(f"  Cache: {cached} SHA256 reports")
    if total < 50:
        print("\n  Tip: run --fetch --all to download training data")
        print("       (requires HYBRID_ANALYSIS_API_KEY env var)")


def main():
    parser = argparse.ArgumentParser(
        description='Hybrid Analysis forensic training data pipeline'
    )
    parser.add_argument('--fetch',       action='store_true',
                        help='Fetch reports from HA API')
    parser.add_argument('--all',         action='store_true',
                        help='Fetch all techniques (use with --fetch)')
    parser.add_argument('--technique',   metavar='TID',
                        help='Fetch one technique (e.g. T1003.001)')
    parser.add_argument('--max-samples', type=int, default=20,
                        help='Max samples per technique (default: 20, free tier: ~6/technique/day)')
    parser.add_argument('--stats',       action='store_true',
                        help='Print dataset statistics and exit')
    args = parser.parse_args()

    if args.stats or not args.fetch:
        print_stats()
        return

    api_key = os.environ.get('HYBRID_ANALYSIS_API_KEY', '')
    if not api_key:
        print('ERROR: HYBRID_ANALYSIS_API_KEY not set')
        print('  Register at: https://www.hybrid-analysis.com/  (free)')
        print('  export HYBRID_ANALYSIS_API_KEY=your_key_here')
        sys.exit(1)

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

    client = HybridAnalysisClient(api_key)

    print(f'\nFetching {len(techniques)} technique(s) — {args.max_samples} samples max each')
    print(f'Rate limit: {60 / _MIN_INTERVAL:.0f} req/min (free tier: 50 req/day)')

    for tid in techniques:
        records = fetch_technique(client, tid, TECHNIQUE_SEARCHES[tid], args.max_samples)
        if records:
            path = save_records(tid, records)
            print(f'  → {len(records)} records saved: {os.path.relpath(path)}')
        else:
            print(f'  → No usable records for {tid}')

    print()
    print_stats()


if __name__ == '__main__':
    main()
