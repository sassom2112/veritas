"""
fast_triage.py

Sub-10-second deterministic scan using ASL-trained patterns.
No LLM, no API calls. Escalates to Claude only if score >= 30.

Usage:
    python3 fast-triage/fast_triage.py /mnt/nromanoff
    python3 fast-triage/fast_triage.py /mnt/xp-tdungan --rules reports/operational_rules.json
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

ESCALATION_THRESHOLD = 50

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_RULES = os.path.normpath(os.path.join(_HERE, '..', 'reports', 'operational_rules.json'))

BASE_PATTERNS = {
    'T1547.001': {
        'name': 'Registry Run Key',
        'signals': ['currentversion\\run', 'runonce', 'dllhost\\svchost',
                    'eventid=13', 'setvalue'],
        'weight': 35,
    },
    'T1036.005': {
        'name': 'Masquerading',
        'signals': ['createremotethread', 'loadlibrary', 'eventid=8',
                    'startaddress', '102400', 'dllhost\\svchost.exe'],
        'weight': 35,
    },
    'T1003.001': {
        'name': 'Credential Dumping',
        'signals': ['mimikatz', 'lsass', 'hydrakatz', 'eventid=10',
                    '0x1fffff', 'sekurlsa'],
        'weight': 35,
    },
    'T1071.001': {
        'name': 'C2 Web Protocol',
        'signals': ['12.190.135.235', '199.73.28.114', 'winclient',
                    'netman', '/ads/'],
        'weight': 35,
    },
    'T1569.002': {
        'name': 'PsExec',
        'signals': ['psexesvc', 'psexec', 'svcctl', 'eventid=7045',
                    '\\admin$\\'],
        'weight': 35,
    },
}

TRIAGE_COMMANDS = [
    # registry_run: grep binary hive directly — no strings needed for exact key name
    ('registry_run',
     "grep -ai 'currentversion.run' "
     "{mount}/Windows/System32/config/SOFTWARE | head -5"),
    # system32_suspicious: find-based, already fast
    ('system32_suspicious',
     "find {mount}/Windows/System32 -name 'svchost.exe' ! -size +100k "
     "| head -10"),
    # psexec_artifacts: find-based, already fast
    ('psexec_artifacts',
     "find {mount} -name 'PSEXESVC.EXE' -o -name 'psexesvc.exe' "
     "| head -10"),
    # network_iocs: targeted binary grep for known C2 IPs only
    ('network_iocs',
     "grep -ac '12.190.135.235\\|199.73.28.114' "
     "{mount}/Windows/System32/config/SOFTWARE"),
    # known_tools: grep binary hive for implant tool names
    ('known_tools',
     "grep -ai 'hydrakatz\\|spinlock\\|hythonize' "
     "{mount}/Windows/System32/config/SOFTWARE | head -5"),
]


def load_rules(rules_path):
    if rules_path and os.path.exists(rules_path):
        with open(rules_path) as f:
            data = json.load(f)
        rules = data.get('rules', {})
        iters = data.get('trained_iterations', 0)
        print(f"  ASL rules loaded ({len(rules)} techniques, "
              f"iteration {iters})")
        return rules
    return BASE_PATTERNS


def scan(text, patterns):
    normalized = text.lower().replace('\\\\', '\\')
    score = 0
    hits = {}
    for tid, data in patterns.items():
        matched = [s for s in data['signals'] if s.lower() in normalized]
        if matched:
            score += data['weight']
            hits[tid] = {'name': data['name'], 'signals': matched,
                         'weight': data['weight']}
    return score, hits


def triage(mount_path, rules):
    t0 = time.time()
    combined_output = []
    command_log = []

    print(f"\n  Running {len(TRIAGE_COMMANDS)} triage checks...")
    for name, cmd_template in TRIAGE_COMMANDS:
        cmd = cmd_template.format(mount=mount_path)
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=15)
        output = result.stdout.strip()
        combined_output.append(output)
        command_log.append({'check': name, 'output_lines': len(output.splitlines())})
        if output:
            print(f"    {name}: {len(output.splitlines())} lines")

    elapsed = time.time() - t0
    combined = '\n'.join(combined_output)
    score, hits = scan(combined, rules)

    return score, hits, elapsed, command_log, combined


def main():
    parser = argparse.ArgumentParser(
        description='Fast deterministic triage — no LLM required'
    )
    parser.add_argument('mount_path', help='Path to mounted image, e.g. /mnt/nromanoff')
    parser.add_argument('--rules', default=_DEFAULT_RULES,
                        help='Path to ASL-trained operational_rules.json')
    args = parser.parse_args()

    if not os.path.isdir(args.mount_path):
        print(f"ERROR: {args.mount_path} not found or not mounted")
        sys.exit(1)

    print(f"\n{'═'*55}")
    print(f"  FAST TRIAGE: {args.mount_path}")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'═'*55}")

    rules = load_rules(args.rules)
    score, hits, elapsed, cmd_log, raw_output = triage(args.mount_path, rules)

    print(f"\n  Elapsed: {elapsed:.1f}s")
    print(f"  Score:   {score}")

    if hits:
        print(f"\n  IOC Hits:")
        for tid, data in hits.items():
            print(f"    {tid} ({data['name']}) +{data['weight']}")
            for sig in data['signals']:
                print(f"      → {sig}")
    else:
        print("  No IOC matches found")

    print()
    if score >= 70:
        verdict = "🔴 HIGH — escalate to full Claude investigation"
    elif score >= ESCALATION_THRESHOLD:
        verdict = "🟡 MEDIUM — escalate to full Claude investigation"
    else:
        verdict = "🟢 LOW — no escalation needed"
    print(f"  {verdict}")

    # Save triage report
    os.makedirs('reports', exist_ok=True)
    host = os.path.basename(args.mount_path.rstrip('/'))
    report_path = f"reports/triage_{host}.json"
    with open(report_path, 'w') as f:
        json.dump({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'target': args.mount_path,
            'elapsed_seconds': round(elapsed, 2),
            'score': score,
            'verdict': verdict,
            'hits': hits,
            'command_log': cmd_log,
        }, f, indent=2)
    print(f"\n  Report saved → {report_path}")
    print(f"{'═'*55}\n")

    return score


if __name__ == '__main__':
    main()
