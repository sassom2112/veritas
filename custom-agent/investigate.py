#!/usr/bin/env python3
"""
investigate.py -- Adversarial Investigation Orchestrator

Sequences: Triage Agent (The Optimist) -> Forensic Auditor (The Cynic)
Produces a unified report and argumentation transcript.

Usage — simple (point at case directory, auto-discovers everything):
    python3 custom-agent/investigate.py --case /cases/nfury
    python3 custom-agent/investigate.py --case /cases/nfury --triage   # fast, no AI loop

Usage — explicit paths (disk must already be mounted):
    python3 custom-agent/investigate.py /mnt/nfury
    python3 custom-agent/investigate.py /mnt/nfury --memory /cases/nfury/mem.001
    python3 custom-agent/investigate.py /mnt/nfury --no-synthesis
"""

import argparse
import asyncio
import glob
import json
import os
import shlex
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


def _discover_case(case_dir: str) -> tuple[str | None, str | None, str]:
    """
    Scan a case directory and return (disk_mount, memory_path, host).

    Finds:
      - *.E01 / *.e01       → disk image (checks common SIFT mount points)
      - *.001 / *.raw / *.img / *.mem  → memory image (used directly)

    Returns disk_mount=None if the E01 is not yet mounted, and prints
    the exact commands needed to mount it.
    """
    case_dir = os.path.realpath(case_dir)
    host     = os.path.basename(case_dir.rstrip('/'))

    # Walk case dir for known file types (one level deep)
    e01_files  = []
    mem_files  = []
    for root, _dirs, files in os.walk(case_dir):
        for fname in files:
            path = os.path.join(root, fname)
            low  = fname.lower()
            if low.endswith('.e01') and not low.endswith('.e01.txt'):
                e01_files.append(path)
            elif any(low.endswith(ext) for ext in ('.001', '.raw', '.img', '.mem', '.vmem')):
                if not low.endswith('.001.txt'):
                    mem_files.append(path)

    memory_path = mem_files[0] if mem_files else None
    if len(mem_files) > 1:
        # Prefer files that look like memory (not split disk segments)
        mem_files = [p for p in mem_files
                     if any(k in p.lower() for k in ('mem', 'ram', 'vmem', 'memory'))]
        memory_path = mem_files[0] if mem_files else memory_path

    disk_mount = None
    if e01_files:
        e01 = e01_files[0]
        # Check common SIFT mount locations
        candidates = [
            f'/mnt/{host}',
            f'/mnt/ewf_{host}',
            '/mnt/windows_mount',
            '/mnt/image_mount',
        ]
        for mp in candidates:
            if os.path.isdir(mp) and os.listdir(mp):
                disk_mount = mp
                break

        if not disk_mount:
            ewf_mp = f'/mnt/ewf_{host}'
            disk_mp = f'/mnt/{host}'
            print(f"\n  ⚠️  E01 found but not mounted: {e01}")
            print(f"  Mount it with:")
            print(f"    sudo mkdir -p {ewf_mp} {disk_mp}")
            print(f"    sudo ewfmount {shlex.quote(e01)} {ewf_mp}")
            print(f"    sudo mmls {ewf_mp}/ewf1   # find the partition offset (sectors)")
            print(f"    sudo mount -o ro,loop,offset=$((OFFSET*512)) {ewf_mp}/ewf1 {disk_mp}")
            print(f"  Then re-run this command.\n")
    else:
        print(f"  ℹ️  No E01 image found in {case_dir} — memory-only investigation")

    return disk_mount, memory_path, host


def _save_unified(host: str, report: dict) -> str:
    path = os.path.join(_REPORTS, f'{host}-investigation.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    return path


# ── CLI entry point ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='ADVERSA Investigation Orchestrator — '
                    'Disk + Memory Triage -> Forensic Auditor -> Unified Report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple — auto-discovers disk mount and memory image from case directory
  python3 custom-agent/investigate.py --case /cases/nfury

  # Fast triage only (deterministic, no AI agentic loop — ~2 min)
  python3 custom-agent/investigate.py --case /cases/nfury --triage

  # Full investigation with explicit paths (disk must be pre-mounted)
  python3 custom-agent/investigate.py /mnt/nfury --memory /cases/nfury/mem.001
        """
    )

    # ── Simple mode ─────────────────────────────────────────────────────────
    parser.add_argument('--case', metavar='CASE_DIR',
                        help='Case directory — auto-discovers disk mount and '
                             'memory image (e.g. /cases/nfury)')
    parser.add_argument('--triage', action='store_true',
                        help='Fast mode: deterministic Pass 1 only, no AI '
                             'agentic loop (~2 min vs ~10 min for full)')

    # ── Explicit mode (advanced) ─────────────────────────────────────────────
    parser.add_argument('target', nargs='?',
                        help='Mounted disk image path (e.g. /mnt/nfury). '
                             'Not needed when using --case.')
    parser.add_argument('ioc_files', nargs='*', metavar='IOC_FILE',
                        help='IOC JSON files from prior investigations. '
                             'Auto-detected from reports/ if omitted.')
    parser.add_argument('--memory', metavar='MEMORY_PATH',
                        help='Raw memory image path (explicit mode only).')
    parser.add_argument('--no-synthesis', action='store_true',
                        help='Alias for --triage.')
    parser.add_argument('--model', metavar='MODEL_ID',
                        default=os.environ.get('ADVERSA_MODEL', 'claude-sonnet-4-6'),
                        help='Claude model for agentic loops '
                             '(default: claude-sonnet-4-6). '
                             'Use claude-opus-4-7 for maximum capability.')
    args = parser.parse_args()
    os.environ['ADVERSA_MODEL'] = args.model
    print(f"  Model: {args.model}")

    # Resolve no-synthesis alias
    no_synthesis = args.triage or args.no_synthesis
    if no_synthesis:
        print("\n  ⚡ TRIAGE MODE — deterministic Pass 1 only, no agentic loop.")
        print("     Use for bulk screening. Run without --triage for full investigation.")
        print("     False negative rate is significant on EVTX-heavy cases (e.g. nfury).\n")

    # ── Case-discovery mode ──────────────────────────────────────────────────
    if args.case:
        if not os.path.isdir(args.case):
            print(f"ERROR: case directory not found: {args.case}")
            sys.exit(1)
        disk_mount, memory_path, host = _discover_case(args.case)

        if not disk_mount and not memory_path:
            print("ERROR: no mounted disk and no memory image found — nothing to investigate")
            sys.exit(1)
        if not disk_mount:
            # Memory-only: still useful
            print(f"  Running memory-only investigation (no mounted disk found)")
            mem_result = asyncio.run(
                memory_agent.investigate(memory_path, host=host, no_synthesis=no_synthesis)
            )
            print(f"\n  Memory score: {mem_result[0]}  techniques: {list(mem_result[1].keys())}")
            return

        ioc_data = _autoload_campaign_iocs(disk_mount, _REPORTS)
        os.environ['BLUE_TARGET'] = disk_mount
        asyncio.run(run_investigation(disk_mount, no_synthesis=no_synthesis,
                                      memory_path=memory_path, ioc_data=ioc_data))
        return

    # ── Explicit mode ────────────────────────────────────────────────────────
    if not args.target:
        parser.print_help()
        sys.exit(1)

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
        ioc_data = _autoload_campaign_iocs(args.target, _REPORTS)

    os.environ['BLUE_TARGET'] = args.target
    asyncio.run(run_investigation(args.target, no_synthesis=no_synthesis,
                                  memory_path=args.memory, ioc_data=ioc_data))


if __name__ == '__main__':
    main()
