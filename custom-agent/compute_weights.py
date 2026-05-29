#!/usr/bin/env python3
from __future__ import annotations
"""
compute_weights.py — Compute calibrated signal weights for VERITAS's scoring engine.

Reads the corpus built by build_corpus.py and produces calibrated_weights.json,
which blue_agent.py loads automatically at startup.

Weight derivation:
  For each (technique, signal) pair:
    p_mal  = P(signal appears | technique is active)  — corpus frequency
    p_ben  = P(signal appears | benign context)        — benign baseline frequency
    log_odds = log2((p_mal + ε) / (p_ben + ε))         — discriminative power
  Normalized to 0–1 and clipped so pure noise = 0, highly specific = 1.

Usage:
    python3 custom-agent/compute_weights.py
    python3 custom-agent/compute_weights.py --min-samples 5 --verbose

Output:
    data/calibrated_weights.json   loaded automatically by blue_agent.py
"""

import argparse
import json
import math
import os
import sys
from pathlib import Path

_HERE      = os.path.dirname(os.path.abspath(__file__))
_CORPUS    = os.path.normpath(os.path.join(_HERE, '..', 'data', 'corpus'))
_OUT_PATH  = os.path.normpath(os.path.join(_HERE, '..', 'data', 'calibrated_weights.json'))

# AV classification metadata labels — these come from MB/HA vx_family and tag strings,
# NOT from forensic disk artifacts. They appear across all technique corpora equally
# and will cause false positives if used as signals. Always filter them out.
_AV_NOISE: frozenset = frozenset({
    # Generic AV verdicts
    'generic', 'generics', 'trojan', 'malware', 'virus', 'suspicious',
    'adware', 'riskware', 'hacktool', 'unwanted', 'potentially',
    # Confidence/scoring metadata from HA reports
    'bounty', 'confidence', 'signed', 'unsigned', 'unknown',
    # AV vendor name fragments appearing in vx_family strings
    'marte', 'securiteinfo', 'win/malicious', 'dump:generic',
    # Generic structural tokens with no forensic meaning
    'application', 'payload', 'shell', 'setup', 'agent',
    # Percentage/scoring artifacts
    '100%',
})

# Version number pattern — BloodHound and other tools submit release filenames
import re as _re
_VERSION_RE = _re.compile(r'^v\d+\.\d+')

# Strings that appear in virtually every Windows disk image — always benign baseline
_BENIGN_STRINGS: list[str] = [
    # System process names
    'svchost', 'lsass', 'explorer', 'csrss', 'winlogon', 'smss', 'wininit',
    'services', 'spoolsv', 'taskhost', 'dllhost', 'conhost', 'rundll32',
    'regsvr32', 'msiexec', 'taskmgr', 'notepad', 'calc', 'regedit',
    # Common DLLs
    'ntdll', 'kernel32', 'user32', 'advapi32', 'msvcrt', 'shell32',
    'ole32', 'rpcrt4', 'comctl32', 'gdi32', 'ws2_32', 'wininet',
    # Registry paths
    'software', 'microsoft', 'windows', 'currentversion', 'system',
    'controlset', 'services', 'runonce', 'policies',
    # Filesystem paths
    'system32', 'syswow64', 'program files', 'programdata', 'users',
    'appdata', 'local', 'roaming', 'temp', 'tmp', 'public', 'desktop',
    # Generic terms
    'version', 'file', 'path', 'name', 'data', 'value', 'key', 'type',
    'service', 'process', 'thread', 'handle', 'module', 'image',
]

# Existing BASE_PATTERNS signals from blue_agent.py — always retain these,
# even if corpus doesn't cover them. They come from known-good case analysis.
_BASE_SIGNALS: dict[str, list[str]] = {
    'T1003.001': ['hydrakatz', 'lsass', 'mimikatz', 'sekurlsa'],
    'T1071.001': ['12.190.135.235', '199.73.28.114', 'winclient'],
    'T1547.001': ['currentversion\\run', 'runonce', 'dllhost/svchost'],
    'T1036.005': ['102400', 'dllhost/svchost.exe'],
    'T1569.002': ['psexesvc', 'psexec', '\\admin$\\'],
    'T1087.001': ['net user /domain', 'seatbelt', 'enumdomainusers',
                  'net localgroup', 'getdomaingroup'],
    'T1059.001': ['wscript.exe', 'cscript.exe', 'powershell -enc',
                  'invoke-expression', 'sharpview', 'netsh advfirewall'],
    'T1560.001': ['record_mic', '7z.exe', 'rar.exe', 'audiocapture'],
    'T1548.002': ['fodhelper', 'eventvwr.exe', 'sdclt.exe',
                  'integritylevel=high', 'fax service'],
}

# Technique metadata for the output file
_TECHNIQUE_META: dict[str, dict] = {
    'T1003.001': {'name': 'OS Credential Dumping: LSASS Memory',  'base_weight': 50},
    'T1071.001': {'name': 'Application Layer Protocol: Web',       'base_weight': 50},
    'T1547.001': {'name': 'Registry Run Keys / Startup Folder',    'base_weight': 45},
    'T1036.005': {'name': 'Masquerading: Match Legitimate Name',   'base_weight': 40},
    'T1569.002': {'name': 'System Services: Service Execution',    'base_weight': 50},
    'T1087.001': {'name': 'Account Discovery: Local Account',      'base_weight': 35},
    'T1059.001': {'name': 'Command & Scripting: PowerShell',       'base_weight': 35},
    'T1560.001': {'name': 'Archive Collected Data',                'base_weight': 35},
    'T1548.002': {'name': 'Abuse Elevation Control: UAC Bypass',   'base_weight': 40},
}


def _load_corpus() -> dict[str, dict]:
    """Load all per-technique corpus files."""
    corpus: dict[str, dict] = {}
    idx_path = os.path.join(_CORPUS, 'corpus_index.json')
    if not os.path.exists(idx_path):
        print(f"ERROR: corpus index not found at {idx_path}")
        print("Run: python3 custom-agent/build_corpus.py")
        sys.exit(1)

    with open(idx_path) as f:
        index = json.load(f)

    for tid, info in index.items():
        fpath = os.path.join(_CORPUS, info['file'])
        if os.path.exists(fpath):
            with open(fpath) as f:
                corpus[tid] = json.load(f)
            print(f"  Loaded {tid}: {info['sample_count']} samples")
    return corpus


def _build_benign_freq() -> dict[str, float]:
    """
    Benign baseline: frequency of each string in clean Windows context.
    1.0 = always present in benign images; 0.0 = never seen in benign images.
    Built from the known-benign string list — strings not in this list get 0.01.
    """
    freq: dict[str, float] = {}
    for s in _BENIGN_STRINGS:
        freq[s.lower()] = 1.0
    return freq


def _is_noise(token: str) -> bool:
    """Return True for AV metadata artifacts that aren't forensic disk signals."""
    t = token.lower().strip()
    if t in _AV_NOISE:
        return True
    if _VERSION_RE.match(t):  # v2.6.0, v2.10.0-rc1, etc.
        return True
    # IP-like strings that are specific IOCs (not noise) — keep them
    if _re.match(r'^\d+\.\d+\.\d+\.\d+$', t):
        return False
    # Pure numeric or single char
    if t.isdigit() or len(t) < 3:
        return True
    return False


def compute_signal_weights(
    corpus: dict[str, dict],
    min_samples: int,
    verbose: bool,
) -> dict[str, dict]:
    """
    For each technique, compute per-signal discriminative weights.
    Returns the calibrated_weights dict ready for JSON serialization.
    """
    benign_freq = _build_benign_freq()
    result: dict[str, dict] = {}
    eps = 0.05  # Laplace smoothing to avoid log(0)

    all_tids = set(_TECHNIQUE_META.keys()) | set(corpus.keys())

    # Identify cross-technique tokens — tokens that appear as corpus signals
    # in 4+ techniques are not technique-specific and should be capped.
    token_technique_count: dict[str, int] = {}
    for tid in all_tids:
        for tok in corpus.get(tid, {}).get('signal_tokens', []):
            if not _is_noise(tok):
                token_technique_count[tok] = token_technique_count.get(tok, 0) + 1
    cross_technique = {t for t, c in token_technique_count.items() if c >= 4}
    if cross_technique:
        print(f"  Cross-technique tokens (capped at 0.2): {sorted(cross_technique)[:10]}")

    for tid in sorted(all_tids):
        meta    = _TECHNIQUE_META.get(tid, {'name': tid, 'base_weight': 35})
        samples = corpus.get(tid, {}).get('samples', [])
        n       = len(samples)

        entry: dict = {
            'name':        meta['name'],
            'base_weight': meta['base_weight'],
            'sample_count': n,
            'signals': {},
        }

        # Collect candidate signals: base signals + corpus tokens (noise filtered)
        candidates: set[str] = set()
        for sig in _BASE_SIGNALS.get(tid, []):
            candidates.add(sig.lower())

        corpus_tokens = corpus.get(tid, {}).get('signal_tokens', [])
        for tok in corpus_tokens[:50]:  # top-50 corpus tokens
            if not _is_noise(tok):
                candidates.add(tok.lower())

        if verbose:
            print(f"\n  {tid} ({n} samples):")

        for sig in sorted(candidates):
            if not sig:
                continue

            # P(signal | malicious) — fraction of samples containing this token
            if n >= min_samples:
                hits = sum(
                    1 for s in samples
                    if sig in (s.get('file_name', '') + ' ' +
                                s.get('submit_name', '') + ' ' +
                                s.get('vx_family', '') + ' ' +
                                ' '.join(s.get('tokens', []))).lower()
                )
                p_mal = hits / n
            else:
                # No corpus data for this technique — use a prior based on how
                # specific the signal string is (length heuristic)
                specificity = min(1.0, len(sig) / 12)
                p_mal = 0.3 + 0.5 * specificity

            # P(signal | benign)
            p_ben = benign_freq.get(sig, 0.01)

            # Log-odds ratio (discriminative power)
            log_odds = math.log2((p_mal + eps) / (p_ben + eps))

            # Normalize: log_odds ≈ 0 → weight 0; log_odds ≥ 4 → weight 1.0
            weight = max(0.0, min(1.0, log_odds / 4.0))

            # Cross-technique tokens are not discriminative — cap at 0.2,
            # UNLESS this signal is part of (or a component of) a base signal
            # for this specific technique (e.g. "powershell" for T1059.001).
            base_sigs_lower = [s.lower() for s in _BASE_SIGNALS.get(tid, [])]
            is_base_related = any(sig in b or b in sig for b in base_sigs_lower)
            if sig in cross_technique and not is_base_related:
                weight = min(weight, 0.2)

            # Baseline signals from known cases always get at least 0.5
            if sig in base_sigs_lower:
                weight = max(weight, 0.5)

            entry['signals'][sig] = round(weight, 3)

            if verbose and weight > 0.1:
                print(f"    {sig:<30} p_mal={p_mal:.2f} p_ben={p_ben:.2f} "
                      f"log_odds={log_odds:+.2f}  weight={weight:.3f}")

        # Sort signals by weight descending for readability
        entry['signals'] = dict(
            sorted(entry['signals'].items(), key=lambda x: -x[1])
        )

        result[tid] = entry

        top = [(k, v) for k, v in entry['signals'].items() if v > 0.5][:5]
        print(f"  {tid}: {len(entry['signals'])} signals, "
              f"top: {[f'{k}={v}' for k,v in top]}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description='Compute calibrated signal weights from VERITAS corpus'
    )
    parser.add_argument('--min-samples', type=int, default=3,
                        help='Min corpus samples needed to use frequency stats (default: 3)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print per-signal weight details')
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  VERITAS Weight Calibration")
    print(f"  min_samples={args.min_samples}  verbose={args.verbose}")
    print(f"{'═'*60}\n")
    print("Loading corpus...")

    corpus = _load_corpus()

    if not corpus:
        print("No corpus data found — computing weights from base signals only")

    print("\nComputing weights...")
    weights = compute_signal_weights(corpus, args.min_samples, args.verbose)

    # Zero out signals that corpus incorrectly promotes — ASL-learned noise
    _ZERO_OVERRIDES: dict[str, list[str]] = {
        'T1059.001': ['svchost.exe', '4663', '5156'],
        'T1087.001': ['5156', 'sesecurityprivilege'],
        'T1548.002': ['consent.exe'],
    }
    for tid, signals in _ZERO_OVERRIDES.items():
        if tid in weights:
            for sig in signals:
                if sig in weights[tid]['signals']:
                    weights[tid]['signals'][sig] = 0.0

    os.makedirs(os.path.dirname(_OUT_PATH), exist_ok=True)
    with open(_OUT_PATH, 'w') as f:
        json.dump(weights, f, indent=2)

    print(f"\n{'═'*60}")
    print(f"  Calibrated weights written: {_OUT_PATH}")
    print(f"  Covers {len(weights)} techniques")
    print(f"{'═'*60}")
    print("\nNext step: re-run investigate.py — weights load automatically.")


if __name__ == '__main__':
    main()
