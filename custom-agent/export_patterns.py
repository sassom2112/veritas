"""
export_patterns.py

Reads brain_state.json after an ASL training run and exports
reliable detection patterns as operational_rules.json.

blue_agent.py loads operational_rules.json at startup so every
forensic investigation uses the latest ASL-trained signals.

Usage:
    python3 export_patterns.py
    python3 export_patterns.py --min-weight 35 --state reports/brain_state.json
"""
import json
import os
import sys
import argparse
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))
_DEFAULT_STATE = os.path.join(_REPORTS, 'brain_state.json')
_DEFAULT_OUTPUT = os.path.join(_REPORTS, 'operational_rules.json')


def _load_domain_rules(state_path: str, domain: str, min_weight: int) -> tuple[dict, int]:
    """Read brain state and return (rules_dict, iteration)."""
    if not os.path.exists(state_path):
        return {}, 0
    with open(state_path) as f:
        state = json.load(f)
    patterns = state.get('blue_patterns', {})
    evasions = state.get('red_evasions', {})
    iteration = state.get('iteration', 0)
    rules = {}
    for tid, data in patterns.items():
        w = data.get('weight', 0)
        s = data.get('signals', [])
        if w >= min_weight and s:
            rules[tid] = {
                'name':          data.get('name', tid),
                'signals':       s,
                'weight':        w,
                'evasions_seen': len(evasions.get(tid, [])),
                'source':        domain,
            }
    return rules, iteration


def export_patterns(state_path=None,
                    output_path=None,
                    min_weight=35,
                    disk_state_path=None):
    if state_path is None:
        state_path = _DEFAULT_STATE
    if output_path is None:
        output_path = _DEFAULT_OUTPUT

    if not os.path.exists(state_path):
        print(f"No brain state found at {state_path} — run brain.py first")
        return None

    with open(state_path) as f:
        state = json.load(f)

    iteration = state.get('iteration', 0)
    patterns = state.get('blue_patterns', {})
    evasions = state.get('red_evasions', {})

    operational_rules = {}
    skipped = []

    for technique_id, data in patterns.items():
        weight = data.get('weight', 0)
        signals = data.get('signals', [])

        if weight >= min_weight and signals:
            operational_rules[technique_id] = {
                'name': data.get('name', technique_id),
                'signals': signals,
                'weight': weight,
                'evasions_seen': len(evasions.get(technique_id, [])),
                'source': 'asl_trained',
            }
        else:
            skipped.append(f"{technique_id} (weight={weight})")

    # ── Merge disk-domain patterns if --disk-state provided ────────────────
    disk_rules, disk_iter = {}, 0
    if disk_state_path:
        disk_rules, disk_iter = _load_domain_rules(
            disk_state_path, 'disk_domain', min_weight
        )
        for tid, drule in disk_rules.items():
            if tid in operational_rules:
                # Merge signals, keeping unique values, source = both
                existing  = operational_rules[tid]
                merged_sigs = list(dict.fromkeys(
                    existing['signals'] + drule['signals']
                ))
                operational_rules[tid] = {
                    **existing,
                    'signals':  merged_sigs,
                    'weight':   max(existing['weight'], drule['weight']),
                    'source':   'asl_trained+disk_domain',
                }
            else:
                operational_rules[tid] = drule
        print(f"Disk-domain rules:   {len(disk_rules)} (iteration {disk_iter})")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump({
            'exported_at':         datetime.now(timezone.utc).isoformat(),
            'trained_iterations':  iteration,
            'disk_iterations':     disk_iter,
            'min_weight_threshold': min_weight,
            'rules':               operational_rules,
        }, f, indent=2)

    print(f"Sysmon training iter: {iteration}")
    print(f"Exported {len(operational_rules)} operational rules → {output_path}")
    if skipped:
        print(f"Skipped (below threshold): {', '.join(skipped)}")
    print()
    for tid, data in operational_rules.items():
        evaded = data['evasions_seen']
        print(f"  {tid} ({data['name']})")
        print(f"    weight={data['weight']}  evasions_seen={evaded}  source={data['source']}")
        print(f"    signals: {data['signals']}")

    return operational_rules


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--min-weight', type=int, default=35)
    parser.add_argument('--state', default=_DEFAULT_STATE)
    parser.add_argument('--disk-state', default=None,
                        help='Forensic-domain brain state to merge (forensic_brain_state.json)')
    parser.add_argument('--output', default=_DEFAULT_OUTPUT)
    parser.add_argument('--no-sigma', action='store_true',
                        help='Skip Sigma rule generation after export')
    args = parser.parse_args()

    rules = export_patterns(args.state, args.output, args.min_weight,
                            disk_state_path=args.disk_state)

    if rules and not args.no_sigma:
        print('\n── Sigma rule generation ──')
        # Resolve sigma_exporter relative to this script
        _here = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, _here)
        from sigma_exporter import export_sigma_rules
        export_sigma_rules(
            rules_path=args.output,
            brain_path=args.state,
        )
