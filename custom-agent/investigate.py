#!/usr/bin/env python3
"""
investigate.py -- Adversarial Investigation Orchestrator

Sequences: Triage Agent (The Optimist) -> Forensic Auditor (The Cynic)
Produces a unified report and argumentation transcript.

The transcript (every Triage finding + every Auditor challenge + every
verdict) is the primary submission artifact demonstrating the adversarial
verification loop.

Usage:
    python3 custom-agent/investigate.py /mnt/nromanoff
    python3 custom-agent/investigate.py /mnt/nfury --no-synthesis
    python3 custom-agent/investigate.py /mnt/controller --no-synthesis
"""

import argparse
import asyncio
import glob
import json
import os
import sys
from datetime import datetime, timezone

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

# Import agents from the same directory
sys.path.insert(0, _HERE)
import blue_agent
import memory_agent
from auditor_agent import ForensicAuditor
from extract_iocs import extract_iocs, merge_iocs
from html_report import generate_report

# Techniques that warrant HIGH verdict regardless of numeric score
_HIGH_VALUE_TECHNIQUES = {'T1003.001', 'T1071.001', 'T1569.002', 'T1547.001'}


# ── Verdict helper ─────────────────────────────────────────────────────────

def _final_verdict(score: int, confirmed: list = None) -> str:
    if confirmed and any(t in _HIGH_VALUE_TECHNIQUES for t in confirmed):
        return 'HIGH — Active compromise confirmed (high-value technique verified on disk)'
    if score >= 70:
        return 'HIGH — Active compromise confirmed'
    elif score >= 40:
        return 'MEDIUM — Suspicious activity, manual review required'
    else:
        return 'LOW — No confirmed compromise indicators'


# ── IOC auto-detection ─────────────────────────────────────────────────────

def _autoload_campaign_iocs(target_path: str, reports_dir: str) -> dict | None:
    """
    When --ioc-file is not passed, look for IOC files from other hosts in reports/.
    Merges all found IOC files and returns the merged dict (or None if none found).
    """
    host = os.path.basename(target_path.rstrip('/'))
    pattern = os.path.join(reports_dir, '*-iocs.json')
    all_ioc_files = sorted(glob.glob(pattern))
    # Exclude the current target's own IOC file (from a previous run)
    other_iocs = [p for p in all_ioc_files
                  if os.path.basename(p) != f'{host}-iocs.json']
    if not other_iocs:
        return None

    print(f"\n  ⚡ Auto-detected campaign IOC files ({len(other_iocs)}):")
    for p in other_iocs:
        print(f"     {os.path.basename(p)}")

    merged = merge_iocs(*other_iocs)
    n_ips   = len(merged.get('c2_ips', []))
    n_files = len(merged.get('filenames', []))
    n_accts = len(merged.get('accounts', []))
    print(f"  ✓  Merged: {n_ips} C2 IPs, {n_files} filenames, {n_accts} accounts\n")
    return merged


# ── Main orchestration loop ────────────────────────────────────────────────

async def run_investigation(target_path: str, no_synthesis: bool = False,
                            ioc_data: dict = None,
                            memory_path: str = None) -> dict:
    """
    Full Triage -> Audit pipeline. Returns unified report dict.
    When memory_path is provided, disk and memory triage run in parallel.
    """
    host = os.path.basename(target_path.rstrip('/'))
    started = datetime.now(timezone.utc)

    print(f"\n{'═'*60}")
    print(f"  ADVERSARIAL INVESTIGATION ORCHESTRATOR")
    print(f"  Framework:  ADVERSA (Adversarial Signal Learning)")
    print(f"  Target:     {target_path}")
    if memory_path:
        print(f"  Memory:     {memory_path}")
    print(f"  Started:    {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'═'*60}")

    # ── Phase 1: Triage Agent (disk) + Memory Agent — parallel ────────────
    rules = blue_agent.load_operational_rules()

    if memory_path:
        print(f"\n{'━'*60}")
        print(f"  PHASE 1  —  DISK + MEMORY TRIAGE  (parallel)")
        print(f"{'━'*60}")
        (triage_score, triage_hits), (mem_score, mem_hits) = await asyncio.gather(
            blue_agent.investigate(
                target_path, rules, no_synthesis=no_synthesis, ioc_data=ioc_data
            ),
            memory_agent.investigate(
                memory_path, host=host, no_synthesis=no_synthesis
            ),
        )
    else:
        print(f"\n{'━'*60}")
        print(f"  PHASE 1  —  TRIAGE AGENT  (The Optimist)")
        print(f"{'━'*60}")
        triage_score, triage_hits = await blue_agent.investigate(
            target_path, rules, no_synthesis=no_synthesis, ioc_data=ioc_data
        )
        mem_score, mem_hits = 0, {}

    triage_report_path = os.path.join(_REPORTS, f'{host}-custom-agent-report.json')
    if not os.path.exists(triage_report_path):
        print(f"\nERROR: Triage report not written to {triage_report_path}")
        sys.exit(1)

    with open(triage_report_path) as f:
        triage_report = json.load(f)

    # Merge disk and memory findings — track source per technique
    disk_techniques = set(triage_report.get('techniques_detected', []))
    mem_techniques  = set(mem_hits.keys())
    all_techniques  = disk_techniques | mem_techniques

    technique_sources = {}
    for tid in all_techniques:
        if tid in disk_techniques and tid in mem_techniques:
            technique_sources[tid] = 'disk+memory'
        elif tid in mem_techniques:
            technique_sources[tid] = 'memory'
        else:
            technique_sources[tid] = 'disk'

    # Merge matched signals
    merged_signals = dict(triage_report.get('matched_signals', {}))
    for tid, sigs in mem_hits.items():
        if tid in merged_signals:
            merged_signals[tid] = list(dict.fromkeys(merged_signals[tid] + sigs))
        else:
            merged_signals[tid] = sigs

    # Combined score: take max of disk/memory, add corroboration bonus
    corroborated = disk_techniques & mem_techniques
    combined_score = min(
        max(triage_score, mem_score)
        + len(corroborated) * 10,   # +10 per technique confirmed in both domains
        100,
    )

    # Build merged triage report for Auditor
    merged_triage = dict(triage_report)
    merged_triage['techniques_detected'] = sorted(all_techniques)
    merged_triage['matched_signals']     = merged_signals
    merged_triage['technique_sources']   = technique_sources
    merged_triage['confidence_score']    = combined_score
    if memory_path:
        merged_triage['memory_path'] = memory_path

    techniques_found = sorted(all_techniques)

    if not techniques_found:
        print("\n  No techniques found in disk or memory — skipping Auditor phase.")
        unified = {
            'generated':     datetime.now(timezone.utc).isoformat(),
            'target':        target_path,
            'memory_path':   memory_path,
            'framework':     'ADVERSA — Adversarial Signal Learning',
            'pipeline':      'Disk+Memory Triage -> Forensic Auditor',
            'triage': {
                'disk_score':        triage_score,
                'memory_score':      mem_score,
                'combined_score':    combined_score,
                'techniques_detected': [],
                'report_path':       triage_report_path,
            },
            'audit':         {'skipped': True, 'reason': 'no_triage_findings'},
            'final_verdict': _final_verdict(combined_score),
            'convergence':   'no_findings_to_challenge',
        }
        _save_unified(host, unified)
        return unified

    # ── Phase 2: Forensic Auditor (The Cynic) ─────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 2  —  FORENSIC AUDITOR  (The Cynic)")
    if technique_sources:
        mem_only  = [t for t, s in technique_sources.items() if s == 'memory']
        disk_only = [t for t, s in technique_sources.items() if s == 'disk']
        both      = [t for t, s in technique_sources.items() if s == 'disk+memory']
        if mem_only:  print(f"  Memory-only:   {mem_only}")
        if disk_only: print(f"  Disk-only:     {disk_only}")
        if both:      print(f"  Corroborated:  {both}")
    print(f"{'━'*60}")

    auditor = ForensicAuditor()
    confirmed, inconclusive, refuted, transcript, adjusted_score = await auditor.audit(
        target_path, merged_triage, memory_path=memory_path
    )

    transcript_path = os.path.join(_REPORTS, f'{host}-auditor-transcript.json')
    total_rounds = sum(len(e['challenges']) for e in transcript)

    # ── Phase 3: Unified report ────────────────────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 3  —  UNIFIED REPORT")
    print(f"{'━'*60}")

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    memory_triage_path = os.path.join(_REPORTS, f'{host}-memory-triage-report.json')

    unified = {
        'generated':   datetime.now(timezone.utc).isoformat(),
        'target':      target_path,
        'memory_path': memory_path,
        'framework':   'ADVERSA — Adversarial Signal Learning',
        'pipeline':    'Disk+Memory Triage -> Forensic Auditor',
        'elapsed_s':   round(elapsed, 1),
        'triage': {
            'disk_score':          triage_score,
            'memory_score':        mem_score,
            'combined_score':      combined_score,
            'techniques_detected': techniques_found,
            'technique_sources':   technique_sources,
            'disk_report_path':    triage_report_path,
            'memory_report_path':  memory_triage_path if memory_path else None,
        },
        'audit': {
            'adjusted_score':       adjusted_score,
            'confirmed':            confirmed,
            'inconclusive':         inconclusive,
            'refuted':              refuted,
            'argumentation_rounds': total_rounds,
            'transcript_path':      transcript_path,
        },
        'final_verdict': _final_verdict(adjusted_score, confirmed=confirmed),
        'convergence':   'all_findings_processed',
    }

    unified_path = _save_unified(host, unified)

    print(f"\n{'═'*60}")
    print(f"  INVESTIGATION COMPLETE  ({elapsed:.0f}s)")
    print(f"")
    print(f"  Disk score:            {triage_score}")
    if memory_path:
        print(f"  Memory score:          {mem_score}")
        print(f"  Combined score:        {combined_score}")
        print(f"  Corroborated:          {corroborated}")
    print(f"  After audit:           {adjusted_score}")
    print(f"  Confirmed techniques:  {confirmed}")
    print(f"  Inconclusive:          {inconclusive}")
    print(f"  Refuted  techniques:   {refuted}")
    print(f"  Argumentation rounds:  {total_rounds}")
    print(f"  Final verdict:         {unified['final_verdict']}")
    print(f"")
    html_path = generate_report(host, _REPORTS)

    # Auto-extract IOCs from confirmed findings for use on subsequent images
    ioc_result  = extract_iocs(host, _REPORTS)
    ioc_path    = os.path.join(_REPORTS, f'{host}-iocs.json')
    with open(ioc_path, 'w') as f:
        import json as _json
        _json.dump(ioc_result, f, indent=2)

    print(f"  Reports written:")
    print(f"    Triage     ->  {triage_report_path}")
    print(f"    Transcript ->  {transcript_path}")
    print(f"    Unified    ->  {unified_path}")
    print(f"    HTML       ->  {html_path}")
    print(f"    IOCs       ->  {ioc_path}  "
          f"({len(ioc_result['c2_ips'])} IPs, "
          f"{len(ioc_result['filenames'])} files, "
          f"{len(ioc_result['accounts'])} accounts)")
    print(f"{'═'*60}\n")

    return unified


def _save_unified(host: str, report: dict) -> str:
    path = os.path.join(_REPORTS, f'{host}-investigation.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    return path


# ── CLI entry point ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Adversarial Investigation Orchestrator — '
                    'Triage Agent -> Forensic Auditor -> Unified Report'
    )
    parser.add_argument('target',
                        help='Mounted image path (e.g. /mnt/nromanoff)')
    parser.add_argument('ioc_files', nargs='*', metavar='IOC_FILE',
                        help='IOC JSON files from prior investigations '
                             '(e.g. reports/nromanoff-iocs.json). '
                             'If omitted, auto-detected from reports/.')
    parser.add_argument('--memory', metavar='MEMORY_PATH',
                        help='Raw memory image path — runs disk and memory '
                             'triage in parallel '
                             '(e.g. /cases/nfury/win7-64-nfury-memory-raw.001)')
    parser.add_argument('--no-synthesis', action='store_true',
                        help='Skip LLM synthesis in Triage phase (faster, '
                             'deterministic two-pass scan only)')
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"ERROR: {args.target} not found or not mounted")
        sys.exit(1)

    if args.memory and not os.path.isfile(args.memory):
        print(f"ERROR: memory image not found: {args.memory}")
        sys.exit(1)

    ioc_data = None
    if args.ioc_files:
        for p in args.ioc_files:
            if not os.path.exists(p):
                print(f"ERROR: IOC file not found: {p}")
                sys.exit(1)
        ioc_data = merge_iocs(*args.ioc_files)
        n = sum(len(v) for v in ioc_data.values() if isinstance(v, list))
        print(f"  IOC files: {args.ioc_files} ({n} IOCs merged)")
    else:
        # Auto-detect IOC files from prior investigations in this campaign
        ioc_data = _autoload_campaign_iocs(args.target, _REPORTS)

    os.environ['BLUE_TARGET'] = args.target
    asyncio.run(run_investigation(args.target, no_synthesis=args.no_synthesis,
                                  memory_path=args.memory,
                                  ioc_data=ioc_data))


if __name__ == '__main__':
    main()
