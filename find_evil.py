#!/usr/bin/env python3
"""
find-evil / VERITAS — Adversarial Forensic Investigator
SANS DFIR Hackathon 2026  |  Category 7: Persistent Learning Loop

Trains a Red vs Blue adversarial loop on real Sysmon telemetry,
learns detection patterns autonomously (ASL), and deploys them as a
dual-agent forensic pipeline with adversarial verification.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.join(_HERE, 'reports')
_AGENT   = os.path.join(_HERE, 'custom-agent')
_TRIAGE  = os.path.join(_HERE, 'fast-triage')

BANNER = """\
╔══════════════════════════════════════════════════════════════╗
║   find-evil / VERITAS  ·  Adversarial Forensic Investigator  ║
║   SANS DFIR Hackathon 2026  ·  Persistent Learning Loop      ║
╚══════════════════════════════════════════════════════════════╝"""

# ── Training state helpers ────────────────────────────────────────────────────

def _training_state() -> dict:
    acc_path = os.path.join(_REPORTS, 'accuracy_report.json')
    rules_path = os.path.join(_REPORTS, 'operational_rules.json')
    state: dict = {}
    if os.path.exists(acc_path):
        with open(acc_path) as f:
            acc = json.load(f)
        ov = acc.get('overall', {})
        state['iterations']      = acc.get('total_iterations', 0)
        state['detection_rate']  = ov.get('detection_rate', 'N/A')
        state['f1']              = ov.get('f1_score', 'N/A')
        state['precision']       = ov.get('precision', 'N/A')
        state['recall']          = ov.get('recall', 'N/A')
        state['techniques']      = acc.get('techniques', {})
    if os.path.exists(rules_path):
        with open(rules_path) as f:
            r = json.load(f)
        state['rules_count']     = len(r.get('rules', {}))
        state['rules_iteration'] = r.get('trained_iterations', 0)
    return state


def _print_banner_with_state():
    print(BANNER)
    s = _training_state()
    if s.get('iterations'):
        print(
            f"\n  GAN  ·  {s['iterations']} iterations  ·  "
            f"detection {s['detection_rate']}  ·  "
            f"F1 {s['f1']}  ·  "
            f"{s.get('rules_count', 0)} techniques loaded\n"
        )
    else:
        print("\n  ⚠  No training state found — run: find-evil --train\n")


# ── Subcommand implementations ────────────────────────────────────────────────

def cmd_status():
    s = _training_state()

    if s.get('iterations'):
        print("  Training metrics:")
        print(f"    Iterations      {s['iterations']}")
        print(f"    Detection rate  {s['detection_rate']}")
        print(f"    Precision       {s['precision']}")
        print(f"    Recall          {s['recall']}")
        print(f"    F1 score        {s['f1']}")
        print()
        print("  Per-technique results:")
        for tid, td in s.get('techniques', {}).items():
            print(f"    {tid}  {td['name']:<30}  "
                  f"det={td['detection_rate']}  "
                  f"patterns={td['patterns_learned']}  "
                  f"evasions={td['red_evasions']}")

    sigma_dir = os.path.join(_REPORTS, 'sigma_rules')
    if os.path.isdir(sigma_dir):
        ymls = [f for f in os.listdir(sigma_dir) if f.endswith('.yml')]
        print(f"\n  Sigma rules exported: {len(ymls)}")
        for y in sorted(ymls):
            print(f"    reports/sigma_rules/{y}")

    reports = sorted(
        f for f in os.listdir(_REPORTS)
        if f.endswith('-custom-agent-report.json')
    )
    if reports:
        print(f"\n  Recent investigation reports:")
        for rname in reports[-5:]:
            rp = os.path.join(_REPORTS, rname)
            with open(rp) as f:
                rd = json.load(f)
            score  = rd.get('confidence_score', '?')
            level  = rd.get('confidence_level', '?')
            techs  = rd.get('techniques_detected', [])
            ps     = rd.get('two_pass_scan') or {}
            delta  = f"  Δ{ps['delta']:+d}" if ps.get('pass2_ran') else ''
            print(f"    {rname}")
            print(f"      score={score} [{level}]{delta}  "
                  f"techniques={techs}")
    print()


def cmd_triage(target: str) -> int:
    """Run fast_triage.py and return the triage score."""
    script = os.path.join(_TRIAGE, 'fast_triage.py')
    subprocess.run([sys.executable, script, target], cwd=_HERE)
    host = os.path.basename(target.rstrip('/'))
    report = os.path.join(_REPORTS, f'triage_{host}.json')
    if os.path.exists(report):
        with open(report) as f:
            return json.load(f).get('score', 0)
    return 0


def cmd_investigate(target: str, no_synthesis: bool = False):
    """Run blue_agent.py (two-pass investigation)."""
    script = os.path.join(_AGENT, 'blue_agent.py')
    cmd = [sys.executable, script, target]
    if no_synthesis:
        cmd.append('--no-synthesis')
    subprocess.run(cmd, cwd=_AGENT)


def cmd_train(iterations: int | None = None):
    """Run brain.py adversarial training loop."""
    script = os.path.join(_AGENT, 'brain.py')
    env = os.environ.copy()
    if iterations:
        env['GAN_ITERATIONS'] = str(iterations)
    subprocess.run([sys.executable, script], cwd=_AGENT, env=env)


def cmd_export():
    """Re-export trained patterns and Sigma rules."""
    script = os.path.join(_AGENT, 'export_patterns.py')
    subprocess.run([sys.executable, script], cwd=_AGENT)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    _print_banner_with_state()

    parser = argparse.ArgumentParser(
        prog='find-evil',
        description='GAN-trained forensic investigator — SANS DFIR Hackathon 2026',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 find_evil.py /mnt/controller                 full pipeline (triage → investigate)
  python3 find_evil.py /mnt/controller --triage-only   fast scan, no API key needed
  python3 find_evil.py /mnt/controller --no-synthesis  two-pass only, skip Claude
  python3 find_evil.py --status                        training state + recent reports
  python3 find_evil.py --train                         run adversarial training (3000 iter)
  python3 find_evil.py --train --iterations 100        short training run
  python3 find_evil.py --export                        re-export rules + Sigma YAML
""",
    )

    parser.add_argument(
        'target', nargs='?',
        help='Mounted image path (e.g. /mnt/nromanoff, /mnt/controller)',
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        '--triage-only', action='store_true',
        help='Fast deterministic triage only — no API key, < 30s',
    )
    mode.add_argument(
        '--investigate-only', action='store_true',
        help='Skip triage, run full two-pass agent directly',
    )
    mode.add_argument(
        '--status', action='store_true',
        help='Show GAN training state, per-technique metrics, recent reports',
    )
    mode.add_argument(
        '--train', action='store_true',
        help='Run Red vs Blue adversarial training loop',
    )
    mode.add_argument(
        '--export', action='store_true',
        help='Export trained patterns → operational_rules.json + Sigma YAML',
    )

    parser.add_argument(
        '--no-synthesis', action='store_true',
        help='Skip Claude LLM synthesis — two-pass deterministic result only',
    )
    parser.add_argument(
        '--iterations', type=int, metavar='N',
        help='Training iterations (used with --train, default: brain.py default)',
    )

    args = parser.parse_args()

    # ── Non-target commands ───────────────────────────────────────────────────
    if args.status:
        cmd_status()
        return

    if args.train:
        print("  Starting adversarial training loop...\n")
        cmd_train(args.iterations)
        return

    if args.export:
        print("  Exporting trained patterns...\n")
        cmd_export()
        return

    # ── Target required from here ─────────────────────────────────────────────
    if not args.target:
        parser.print_help()
        sys.exit(0)

    if not os.path.isdir(args.target):
        print(f"  ERROR: {args.target} — not found or not a directory\n")
        print("  Mount the image first, e.g.:")
        print("    sudo ewfmount image.E01 /mnt/ewf")
        print("    sudo mount -o ro,norecovery /mnt/ewf/ewf1 /mnt/controller\n")
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f"  Target : {args.target}")
    print(f"  UTC    : {ts}\n")

    # ── Triage-only ───────────────────────────────────────────────────────────
    if args.triage_only:
        cmd_triage(args.target)
        return

    # ── Investigate-only ──────────────────────────────────────────────────────
    if args.investigate_only:
        cmd_investigate(args.target, args.no_synthesis)
        return

    # ── Default: full pipeline (triage → auto-escalate → investigate) ─────────
    print("  ┌─ Phase 1/2  Fast Triage ─────────────────────────────────────┐")
    score = cmd_triage(args.target)
    print("  └──────────────────────────────────────────────────────────────┘\n")

    if score >= 30:
        print(f"  Triage score {score} ≥ 30 — auto-escalating to full investigation\n")
        print("  ┌─ Phase 2/2  Two-Pass Agent Investigation ────────────────────┐")
        cmd_investigate(args.target, args.no_synthesis)
        print("  └──────────────────────────────────────────────────────────────┘")
    else:
        print(f"  Triage score {score} < 30 — no escalation needed")
        host = os.path.basename(args.target.rstrip('/'))
        print(f"  Report saved → reports/triage_{host}.json\n")


if __name__ == '__main__':
    main()
