#!/usr/bin/env python3
"""
investigate.py -- VERITAS Investigation Orchestrator

Sequences: Disk Agent + Memory Agent -> Forensic Auditor -> Unified Report
Both phases always run. The Auditor is not optional.

Usage — case directory (auto-discovers disk mount + memory):
    python3 custom-agent/investigate.py --case /cases/nfury

Campaign mode — explicitly name other hosts in the same investigation:
    python3 custom-agent/investigate.py --case /cases/tdungan nfury
    python3 custom-agent/investigate.py --case /cases/tdungan nfury nromanoff controller

Each named host resolves to reports/<host>-iocs.json. No IOCs are injected
unless you name them here — no automatic cross-campaign contamination.

Usage — explicit paths (disk must already be mounted):
    python3 custom-agent/investigate.py /mnt/nfury
    python3 custom-agent/investigate.py /mnt/nfury --memory /cases/nfury/mem.001
"""

import argparse
import asyncio
import json
import os
import shlex
import sys
from datetime import datetime, timezone

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

TARGET_MAX_COST_USD = 20.0   # abort Phase 3 if Phase 1+2 already exceeded this

# VERITAS case_io — writes auditor findings as DRAFT for human approval
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, '..', 'src')))
try:
    from adversa.case_io import init_case, write_findings_from_audit, get_examiner
    _CASE_IO_AVAILABLE = True
except ImportError:
    _CASE_IO_AVAILABLE = False

# Import agents from the same directory
sys.path.insert(0, _HERE)
import blue_agent
import memory_agent
from auditor_agent import ForensicAuditor
from contracts import AuditResult, FinalTechniqueResult, TriageHandoff
from cross_verifier import CrossVerifier, adjudicate
from disk_agent import DiskAgent
from metrics import Metrics
from verifier import verify_same_layer
from extract_iocs import extract_iocs, merge_iocs
from html_report import generate_report

# Techniques that warrant HIGH verdict regardless of numeric score
_HIGH_VALUE_TECHNIQUES = {'T1003.001', 'T1071.001', 'T1569.002', 'T1547.001'}


# ── Verdict helper ─────────────────────────────────────────────────────────

def _final_verdict(score: int, confirmed: list = None) -> str:
    confirmed = confirmed or []
    if any(t in _HIGH_VALUE_TECHNIQUES for t in confirmed):
        return 'HIGH — Active compromise confirmed (high-value technique verified on disk)'
    if len(confirmed) >= 3:
        return 'HIGH — Active compromise confirmed'
    if len(confirmed) >= 1:
        return 'MEDIUM — Suspicious activity, manual review required'
    return 'LOW — No confirmed compromise indicators'


# ── IOC auto-detection ─────────────────────────────────────────────────────

def _resolve_campaign_iocs(hosts_or_paths: list, reports_dir: str) -> dict | None:
    """
    Resolve explicit campaign members to IOC data.

    Each entry is either:
      - a hostname ('nfury', 'controller')  -> reports/nfury-iocs.json
      - a file path ('/path/to/host-iocs.json') -> used directly

    No auto-detection. Only what you name gets injected.
    """
    if not hosts_or_paths:
        return None

    resolved = []
    for entry in hosts_or_paths:
        if os.sep in entry or entry.endswith('.json'):
            if not os.path.exists(entry):
                print(f"ERROR: IOC file not found: {entry}")
                sys.exit(1)
            resolved.append(entry)
        else:
            path = os.path.join(reports_dir, f'{entry}-iocs.json')
            if not os.path.exists(path):
                print(f"ERROR: no IOC file for host '{entry}' — expected {path}")
                sys.exit(1)
            resolved.append(path)

    print(f"\n  Campaign hosts ({len(resolved)}):")
    for p in resolved:
        print(f"     {os.path.basename(p)}")

    merged = merge_iocs(*resolved)
    n_ips   = len(merged.get('c2_ips', []))
    n_files = len(merged.get('filenames', []))
    n_accts = len(merged.get('accounts', []))
    print(f"  ✓  Merged: {n_ips} C2 IPs, {n_files} filenames, {n_accts} accounts\n")
    return merged


# ── Main orchestration loop ────────────────────────────────────────────────

async def run_cross_layer(
    target_path: str,
    memory_path: str | None = None,
    ioc_data: dict | None = None,
) -> dict:
    """
    Cross-layer investigation pipeline (future/cross-layer-verification branch).

    Architecture:
      1. DiskAgent and memory_agent.investigate_layered() run in parallel
         with disjoint tool grants (VERITAS_LAYER=disk / VERITAS_LAYER=memory).
      2. Same-layer blind replication (PRIMARY GATE): fresh sessions per claim,
         same layer's tools, receives tool_output + artifact_hint only — no reasoning.
      3. Cross-layer corroboration (BONUS): CONFIRMED claims only, opposite layer.
         Disk claims → memory verifier.  Memory claims → disk verifier.
      4. Adjudication: same-layer drives verdict, cross-layer annotates.
         HIGH_CONFIRMED | CONFIRMED | DISPUTED | REFUTED | INCONCLUSIVE.
    """
    from memory_agent import investigate_layered as mem_investigate_layered

    host    = os.path.basename(target_path.rstrip('/'))
    started = datetime.now(timezone.utc)
    metrics = Metrics()

    print(f"\n{'═'*60}")
    print(f"  VERITAS CROSS-LAYER INVESTIGATION")
    print(f"  Target:   {target_path}")
    if memory_path:
        print(f"  Memory:   {memory_path}")
    print(f"  Started:  {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'═'*60}")

    # ── Phase 1: Parallel disjoint-grant investigation ─────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 1  —  PARALLEL INVESTIGATION  (disjoint tool grants)")
    print(f"{'━'*60}")

    metrics.start_phase('phase_1_disk')
    metrics.start_phase('phase_1_memory')
    disk_task = DiskAgent().investigate(target_path, ioc_data=ioc_data)
    if memory_path:
        mem_task  = mem_investigate_layered(memory_path, host=host)
        (disk_claims, memory_claims) = await asyncio.gather(disk_task, mem_task)
    else:
        disk_claims  = await disk_task
        memory_claims = []
    metrics.end_phase('phase_1_disk')
    metrics.end_phase('phase_1_memory')

    print(f"\n  Phase 1 complete: {len(disk_claims)} disk claims, "
          f"{len(memory_claims)} memory claims")

    # ── Phase 2: Same-layer blind replication (PRIMARY GATE) ──────────────
    all_claims = disk_claims + memory_claims
    metrics.start_phase('phase_2_verify')
    same_layer_verdicts = await verify_same_layer(all_claims, target_path, memory_path, metrics)
    metrics.end_phase('phase_2_verify')

    same_verdict_map = {v['technique_id']: v for v in same_layer_verdicts}
    confirmed_disk   = [c for c in disk_claims
                        if same_verdict_map.get(c['technique_id'], {}).get('verdict') == 'CONFIRMED']
    confirmed_memory = [c for c in memory_claims
                        if same_verdict_map.get(c['technique_id'], {}).get('verdict') == 'CONFIRMED']

    phase_2_cost = metrics.total_cost_usd()
    print(f"\n  Phase 2 gate: {len(confirmed_disk)} disk / {len(confirmed_memory)} memory pass to Phase 3")
    print(f"  Phase 2 cost so far: ${phase_2_cost:.4f}")

    # ── Cost ceiling gate — abort Phase 3 if already over budget ──────────
    if phase_2_cost > TARGET_MAX_COST_USD:
        print(f"\n  COST CEILING REACHED (${phase_2_cost:.2f} > ${TARGET_MAX_COST_USD:.2f})")
        print(f"  Skipping Phase 3. Cross-layer corroboration set to NO_VISIBILITY.")
        disk_verdicts   = []
        memory_verdicts = []
    else:
        # ── Phase 3: Cross-layer corroboration (CONFIRMED claims only) ─────
        print(f"\n{'━'*60}")
        print(f"  PHASE 3  —  CROSS-LAYER CORROBORATION")
        print(f"  Confirmed disk → memory verifier | Confirmed memory → disk verifier")
        print(f"{'━'*60}")

        metrics.start_phase('phase_3_cross')
        disk_verdicts, memory_verdicts = await CrossVerifier().verify_all(
            confirmed_disk, confirmed_memory, target_path, memory_path, metrics
        )
        metrics.end_phase('phase_3_cross')

    # ── Phase 4: Adjudication and report ───────────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 4  —  ADJUDICATION")
    print(f"{'━'*60}")

    results = adjudicate(same_layer_verdicts, disk_claims, memory_claims,
                         disk_verdicts, memory_verdicts)

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    high_confirmed = [r for r in results if r['final'] == 'HIGH_CONFIRMED']
    confirmed      = [r for r in results if r['final'] == 'CONFIRMED']
    disputed       = [r for r in results if r['final'] == 'DISPUTED']
    refuted        = [r for r in results if r['final'] == 'REFUTED']
    inconclusive   = [r for r in results if r['final'] == 'INCONCLUSIVE']

    if high_confirmed:
        print(f"\n  HIGH_CONFIRMED (same-layer + cross-layer corroborated): {len(high_confirmed)}")
        for r in high_confirmed:
            print(f"    {r['technique_id']}  [{r['source_layer']}]  {(r['citation'] or '')[:50]}")
    print(f"  CONFIRMED (same-layer verified, no cross-layer visibility): {len(confirmed)}")
    for r in confirmed:
        print(f"    {r['technique_id']}  [{r['source_layer']}]")
    if disputed:
        print(f"  DISPUTED (same-layer confirmed, cross-layer contradicted): {len(disputed)}")
        for r in disputed:
            print(f"    {r['technique_id']}  *** HUMAN REVIEW REQUIRED ***")
    print(f"  REFUTED (same-layer found contradicting evidence): {len(refuted)}")
    print(f"  INCONCLUSIVE (same-layer insufficient visibility): {len(inconclusive)}")

    unified = {
        'generated':       datetime.now(timezone.utc).isoformat(),
        'target':          target_path,
        'memory_path':     memory_path,
        'pipeline':        'cross-layer-verification',
        'elapsed_s':       round(elapsed, 1),
        'disk_claims':     len(disk_claims),
        'memory_claims':   len(memory_claims),
        'high_confirmed':  [r['technique_id'] for r in high_confirmed],
        'confirmed':       [r['technique_id'] for r in confirmed],
        'disputed':        [r['technique_id'] for r in disputed],
        'refuted':         [r['technique_id'] for r in refuted],
        'inconclusive':    [r['technique_id'] for r in inconclusive],
        'results':         list(results),
    }

    path = os.path.join(_REPORTS, f'{host}-cross-layer-investigation.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(unified, f, indent=2)

    verdicts_summary = {
        'HIGH_CONFIRMED': len(high_confirmed),
        'CONFIRMED':      len(confirmed),
        'DISPUTED':       len(disputed),
        'REFUTED':        len(refuted),
        'INCONCLUSIVE':   len(inconclusive),
    }
    manifest = metrics.to_dict(case_id=host, host=host, verdicts_summary=verdicts_summary)
    manifest_path = os.path.join(_REPORTS, f'{host}-audit-manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"  Manifest:        {manifest_path}  (${manifest['total_cost_usd']:.4f} total)")

    print(f"\n{'═'*60}")
    print(f"  CROSS-LAYER INVESTIGATION COMPLETE  ({elapsed:.0f}s)")
    print(f"  High confirmed:  {len(high_confirmed)}")
    print(f"  Confirmed:       {len(confirmed)}")
    print(f"  Disputed:        {len(disputed)}")
    print(f"  Refuted:         {len(refuted)}")
    print(f"  Inconclusive:    {len(inconclusive)}")
    print(f"  Report:          {path}")
    print(f"{'═'*60}\n")

    return unified


async def run_investigation(target_path: str,
                            ioc_data: dict = None,
                            memory_path: str = None) -> dict:
    """
    Full Triage -> Audit pipeline. Returns unified report dict.
    When memory_path is provided, disk and memory triage run in parallel.
    Both phases always run — the Auditor is not optional.
    """
    host = os.path.basename(target_path.rstrip('/'))
    started = datetime.now(timezone.utc)

    print(f"\n{'═'*60}")
    print(f"  VERITAS INVESTIGATION ORCHESTRATOR")
    print(f"  Framework:  VERITAS")
    print(f"  Target:     {target_path}")
    if memory_path:
        print(f"  Memory:     {memory_path}")
    print(f"  Started:    {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'═'*60}")

    # ── Phase 1: Disk Agent + Memory Agent — parallel ─────────────────────
    rules = blue_agent.load_operational_rules()

    if memory_path:
        print(f"\n{'━'*60}")
        print(f"  PHASE 1  —  DISK + MEMORY TRIAGE  (parallel)")
        print(f"{'━'*60}")
        (triage_score, triage_hits), (mem_score, mem_hits) = await asyncio.gather(
            blue_agent.investigate(target_path, rules, ioc_data=ioc_data),
            memory_agent.investigate(memory_path, host=host),
        )
    else:
        print(f"\n{'━'*60}")
        print(f"  PHASE 1  —  TRIAGE AGENT")
        print(f"{'━'*60}")
        triage_score, triage_hits = await blue_agent.investigate(
            target_path, rules, ioc_data=ioc_data
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
            'framework':     'VERITAS',
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

    # ── Phase 2: Forensic Auditor ──────────────────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 2  —  FORENSIC AUDITOR")
    if technique_sources:
        mem_only  = [t for t, s in technique_sources.items() if s == 'memory']
        disk_only = [t for t, s in technique_sources.items() if s == 'disk']
        both      = [t for t, s in technique_sources.items() if s == 'disk+memory']
        if mem_only:  print(f"  Memory-only:   {mem_only}")
        if disk_only: print(f"  Disk-only:     {disk_only}")
        if both:      print(f"  Corroborated:  {both}")
    print(f"{'━'*60}")

    auditor      = ForensicAuditor()
    audit_result: AuditResult = await auditor.audit(
        target_path, merged_triage, memory_path=memory_path
    )
    confirmed      = audit_result['confirmed']
    inconclusive   = audit_result['inconclusive']
    refuted        = audit_result['refuted']
    transcript     = audit_result['transcript']
    adjusted_score = audit_result['adjusted_score']

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
        'framework':   'VERITAS',
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

    # Write findings to case directory as DRAFT — require `adversa approve` to sign
    if _CASE_IO_AVAILABLE:
        examiner  = get_examiner()
        case_dir  = init_case(host)
        write_findings_from_audit(
            case_dir, host,
            confirmed, inconclusive, refuted, transcript, examiner,
        )
        print(f"\n  Case directory: {case_dir}")
        print(f"  Findings written as DRAFT — human approval required:")
        print(f"    adversa review {case_dir}")
        print(f"    adversa approve {case_dir} <finding_id>")

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
        description='VERITAS Investigation Orchestrator — '
                    'Disk + Memory Triage -> Forensic Auditor -> Unified Report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple — auto-discovers disk mount and memory image from case directory
  python3 custom-agent/investigate.py --case /cases/nfury

  # Full investigation with explicit paths (disk must be pre-mounted)
  python3 custom-agent/investigate.py /mnt/nfury --memory /cases/nfury/mem.001
        """
    )

    # ── Simple mode ─────────────────────────────────────────────────────────
    parser.add_argument('--case', metavar='CASE_DIR',
                        help='Case directory — auto-discovers disk mount and '
                             'memory image (e.g. /cases/nfury)')
    parser.add_argument('--cross-layer', action='store_true',
                        help='Cross-layer verification pipeline: disjoint tool grants, '
                             'each layer verifies the other. Produces CONFIRMED | '
                             'SINGLE_SOURCE | DISPUTED verdicts.')

    # ── Explicit mode (advanced) ─────────────────────────────────────────────
    parser.add_argument('target', nargs='?',
                        help='Mounted disk image path (e.g. /mnt/nfury). '
                             'Not needed when using --case.')
    parser.add_argument('campaign', nargs='*', metavar='HOST',
                        help='Other hosts in this campaign whose IOCs should be '
                             'injected (e.g. nfury nromanoff). Resolved to '
                             'reports/<host>-iocs.json. Full paths also accepted. '
                             'Nothing is injected if omitted.')
    parser.add_argument('--memory', metavar='MEMORY_PATH',
                        help='Raw memory image path (explicit mode only).')
    parser.add_argument('--model', metavar='MODEL_ID',
                        default=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                        help='Claude model for agentic loops '
                             '(default: claude-sonnet-4-6). '
                             'Use claude-opus-4-7 for maximum capability.')
    args = parser.parse_args()
    os.environ['VERITAS_MODEL'] = args.model
    print(f"  Model: {args.model}")

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
                memory_agent.investigate(memory_path, host=host)
            )
            print(f"\n  Memory score: {mem_result[0]}  techniques: {list(mem_result[1].keys())}")
            return

        ioc_data = _resolve_campaign_iocs(args.campaign, _REPORTS)
        os.environ['BLUE_TARGET'] = disk_mount
        if args.cross_layer:
            asyncio.run(run_cross_layer(disk_mount, memory_path=memory_path, ioc_data=ioc_data))
        else:
            asyncio.run(run_investigation(disk_mount, memory_path=memory_path, ioc_data=ioc_data))
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

    ioc_data = _resolve_campaign_iocs(args.campaign, _REPORTS)

    os.environ['BLUE_TARGET'] = args.target
    if args.cross_layer:
        asyncio.run(run_cross_layer(args.target, memory_path=args.memory, ioc_data=ioc_data))
    else:
        asyncio.run(run_investigation(args.target, memory_path=args.memory, ioc_data=ioc_data))


if __name__ == '__main__':
    main()
