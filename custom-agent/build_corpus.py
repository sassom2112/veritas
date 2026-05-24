#!/usr/bin/env python3
"""
build_corpus.py — Collect labeled malware samples from MalwareBazaar + HybridAnalysis
and build a signal corpus for compute_weights.py to calibrate ADVERSA's scoring engine.

Usage:
    export MB_API_KEY=<your-key>      # MalwareBazaar (free, register at abuse.ch)
    export HA_API_KEY=<your-key>      # Hybrid Analysis (free tier sufficient)
    python3 custom-agent/build_corpus.py
    python3 custom-agent/build_corpus.py --technique T1003.001 --limit 50

Output:
    data/corpus/<technique>-samples.json   per-technique labeled samples
    data/corpus/corpus_index.json          summary index

MalwareBazaar API: https://mb-api.abuse.ch/api/v1/  (no key required for public queries)
HybridAnalysis API: https://www.hybrid-analysis.com/api/v2/  (free API key needed)
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_CORPUS  = os.path.normpath(os.path.join(_HERE, '..', 'data', 'corpus'))
_MB_URL  = 'https://mb-api.abuse.ch/api/v1/'
_HA_URL  = 'https://www.hybrid-analysis.com/api/v2'

# Map MB tags / malware family substrings → MITRE technique
# Multiple tags can map to the same technique; a sample maps to the first match.
_TAG_MAP: list[tuple[str, str]] = [
    # T1003.001 — Credential Dumping: LSASS
    ('mimikatz',         'T1003.001'),
    ('lazagne',          'T1003.001'),
    ('credential',       'T1003.001'),
    ('procdump',         'T1003.001'),
    ('nanodump',         'T1003.001'),
    ('dumpert',          'T1003.001'),
    # T1071.001 — C2 Web Protocol
    ('cobalt',           'T1071.001'),
    ('cobaltstrike',     'T1071.001'),
    ('meterpreter',      'T1071.001'),
    ('beacon',           'T1071.001'),
    ('havoc',            'T1071.001'),
    ('sliver',           'T1071.001'),
    ('brute-ratel',      'T1071.001'),
    # T1569.002 — Service Execution / PsExec
    ('psexec',           'T1569.002'),
    ('paexec',           'T1569.002'),
    ('remcom',           'T1569.002'),
    # T1087.001 — Account Discovery
    ('bloodhound',       'T1087.001'),
    ('sharphound',       'T1087.001'),
    ('adrecon',          'T1087.001'),
    ('pingcastle',       'T1087.001'),
    # T1059.001 — PowerShell Execution
    ('powershell',       'T1059.001'),
    ('empire',           'T1059.001'),
    ('nishang',          'T1059.001'),
    ('powercat',         'T1059.001'),
    # T1560.001 — Archive Collected Data
    ('7zip',             'T1560.001'),
    ('winrar',           'T1560.001'),
    ('archiver',         'T1560.001'),
    # T1548.002 — UAC Bypass
    ('uac-bypass',       'T1548.002'),
    ('uacme',            'T1548.002'),
    # T1547.001 — Registry Run Key Persistence
    ('persistence',      'T1547.001'),
    ('autorun',          'T1547.001'),
    # T1036.005 — Masquerading
    ('process-hollow',   'T1036.005'),
    ('hollow',           'T1036.005'),
    ('masquerad',        'T1036.005'),
]

# Tags in MB that are malware-family-generic (not technique-specific) — skip as primary
_SKIP_TAGS = frozenset({
    'exe', 'dll', 'pe32', 'trojan', 'malware', 'virus', 'ransomware',
    'infostealer', 'backdoor', 'dropper', 'loader', 'rat', 'apt',
})

# Strings that always appear in benign Windows artifacts — useless as signals
_BENIGN_TOKENS = frozenset({
    'windows', 'microsoft', 'system', 'system32', 'syswow64',
    'program', 'files', 'users', 'public', 'default', 'local',
    'service', 'svchost', 'explorer', 'notepad', 'cmd', 'win',
    'dll', 'exe', 'sys', 'tmp', 'log', 'bin', 'cfg', 'ini',
    'x64', 'x86', 'win32', 'win64', 'amd64', 'i386',
    'version', 'release', 'debug', 'build', 'src', 'obj',
    'true', 'false', 'null', 'none', 'error', 'ok', 'info',
})


def _tag_to_technique(tags: list[str]) -> str | None:
    """Return first technique match for a list of tags."""
    for tag in tags:
        tag_lower = tag.lower()
        for pattern, tid in _TAG_MAP:
            if pattern in tag_lower:
                return tid
    return None


def _extract_tokens(s: str) -> list[str]:
    """Extract meaningful tokens from a filename or family string."""
    # Split on dots, underscores, hyphens, spaces, camel-case boundaries
    parts = re.split(r'[.\-_\s]+', s.lower())
    # Also split camel-case: "CobaltStrike" → ["cobalt", "strike"]
    expanded = []
    for p in parts:
        subs = re.sub(r'([a-z])([A-Z])', r'\1 \2', p).split()
        expanded.extend(subs)
    tokens = [t for t in expanded
              if len(t) >= 4
              and t not in _BENIGN_TOKENS
              and not t.isdigit()]
    return tokens


def mb_query_tag(tag: str, limit: int, session: requests.Session) -> list[dict]:
    """Query MalwareBazaar for samples with a given tag."""
    try:
        resp = session.post(
            _MB_URL,
            data={'query': 'get_taginfo', 'tag': tag, 'limit': limit},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get('query_status') != 'ok':
            print(f"    MB [{tag}]: {data.get('query_status', 'unknown')}")
            return []
        return data.get('data', []) or []
    except Exception as e:
        print(f"    MB [{tag}] error: {e}")
        return []


def ha_summary(sha256: str, api_key: str, session: requests.Session) -> dict | None:
    """Fetch HybridAnalysis summary for a SHA256."""
    if not api_key:
        return None
    try:
        resp = session.get(
            f'{_HA_URL}/report/{sha256}/summary',
            headers={'api-key': api_key, 'User-Agent': 'Falcon Sandbox'},
            timeout=20,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"    HA [{sha256[:12]}] error: {e}")
        return None


def collect(techniques: list[str] | None, limit_per_tag: int, ha_key: str) -> dict:
    """
    Build corpus dict: {technique: {samples: [...], signal_tokens: [...]}}
    """
    corpus: dict = {}
    seen_sha: set[str] = set()
    session = requests.Session()
    session.headers['User-Agent'] = 'adversa-corpus-builder/1.0'

    target_tags = [
        (tag, tid) for tag, tid in _TAG_MAP
        if techniques is None or tid in techniques
    ]

    for tag, tid in target_tags:
        print(f"\n  [{tid}] Querying MB tag: {tag}")
        samples_raw = mb_query_tag(tag, limit_per_tag, session)
        print(f"    → {len(samples_raw)} samples returned")

        for raw in samples_raw:
            sha = raw.get('sha256_hash', '')
            if not sha or sha in seen_sha:
                continue
            seen_sha.add(sha)

            entry: dict = {
                'sha256':      sha,
                'technique':   tid,
                'mb_tag':      tag,
                'file_name':   raw.get('file_name', ''),
                'file_type':   raw.get('file_type', ''),
                'first_seen':  raw.get('first_seen', ''),
                'submit_name': '',
                'vx_family':   '',
                'verdict':     '',
                'domains':     [],
                'hosts':       [],
                'tokens':      [],
            }

            # Tokens from MB filename
            if entry['file_name']:
                entry['tokens'].extend(_extract_tokens(entry['file_name']))

            # Tokens from MB tags
            for t in raw.get('tags', []) or []:
                if t.lower() not in _SKIP_TAGS and len(t) >= 4:
                    entry['tokens'].append(t.lower())

            # Enrich with HA summary
            if ha_key:
                time.sleep(0.5)  # HA rate limit: 2 req/s on free tier
                ha = ha_summary(sha, ha_key, session)
                if ha:
                    entry['submit_name'] = ha.get('submit_name', '')
                    entry['vx_family']   = ha.get('vx_family', '') or ''
                    entry['verdict']     = ha.get('verdict', '')
                    entry['domains']     = ha.get('domains', []) or []
                    entry['hosts']       = ha.get('hosts', []) or []
                    if entry['submit_name']:
                        entry['tokens'].extend(_extract_tokens(entry['submit_name']))
                    if entry['vx_family']:
                        entry['tokens'].extend(_extract_tokens(entry['vx_family']))

            entry['tokens'] = sorted(set(entry['tokens']))

            if tid not in corpus:
                corpus[tid] = {'samples': [], 'signal_tokens': []}
            corpus[tid]['samples'].append(entry)

            # Accumulate all tokens seen for this technique
            corpus[tid]['signal_tokens'].extend(entry['tokens'])

        # Pause between tag queries to respect MB rate limit
        time.sleep(1.5)

    # Deduplicate and rank signal tokens by frequency
    for tid, data in corpus.items():
        token_freq: dict[str, int] = {}
        for tok in data['signal_tokens']:
            token_freq[tok] = token_freq.get(tok, 0) + 1
        # Keep tokens appearing in ≥2 samples, sorted by frequency descending
        data['signal_tokens'] = [
            t for t, _ in sorted(token_freq.items(), key=lambda x: -x[1])
            if token_freq[t] >= 2
        ]
        print(f"\n  {tid}: {len(data['samples'])} samples, "
              f"{len(data['signal_tokens'])} distinct signal tokens")
        if data['signal_tokens']:
            print(f"    top tokens: {data['signal_tokens'][:10]}")

    return corpus


def save_corpus(corpus: dict) -> None:
    os.makedirs(_CORPUS, exist_ok=True)
    index = {}
    for tid, data in corpus.items():
        path = os.path.join(_CORPUS, f'{tid.replace(".", "_")}-samples.json')
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        index[tid] = {
            'file':         os.path.basename(path),
            'sample_count': len(data['samples']),
            'top_tokens':   data['signal_tokens'][:20],
        }
        print(f"  Saved {path}")

    idx_path = os.path.join(_CORPUS, 'corpus_index.json')
    with open(idx_path, 'w') as f:
        json.dump(index, f, indent=2)
    print(f"\nCorpus index: {idx_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Build ADVERSA signal corpus from MalwareBazaar + HybridAnalysis'
    )
    parser.add_argument('--technique', nargs='+',
                        metavar='TID',
                        help='Limit to specific techniques (e.g. T1003.001 T1071.001)')
    parser.add_argument('--limit', type=int, default=100,
                        help='Max samples per MB tag query (default: 100)')
    parser.add_argument('--no-ha', action='store_true',
                        help='Skip HybridAnalysis enrichment (MB only)')
    args = parser.parse_args()

    mb_key = os.environ.get('MB_API_KEY', '')   # MB is public; key not required
    ha_key = '' if args.no_ha else os.environ.get('HA_API_KEY', '')

    if not ha_key and not args.no_ha:
        print("ℹ️  HA_API_KEY not set — HybridAnalysis enrichment skipped")
        print("   Set HA_API_KEY or pass --no-ha to suppress this message")

    print(f"\n{'═'*60}")
    print(f"  ADVERSA Corpus Builder")
    print(f"  MB limit per tag: {args.limit}  |  HA enrichment: {'yes' if ha_key else 'no'}")
    print(f"{'═'*60}")

    corpus = collect(
        techniques=args.technique,
        limit_per_tag=args.limit,
        ha_key=ha_key,
    )

    if not corpus:
        print("\nNo samples collected — check network connectivity and API keys.")
        sys.exit(1)

    save_corpus(corpus)
    total = sum(len(d['samples']) for d in corpus.values())
    print(f"\nDone: {total} samples across {len(corpus)} techniques.")
    print("Next step: python3 custom-agent/compute_weights.py")


if __name__ == '__main__':
    main()
