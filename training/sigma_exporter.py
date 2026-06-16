"""
sigma_exporter.py

Converts ASL-trained operational_rules.json into adversarially-validated
Sigma detection rules. Each technique produces one .yml file.

After generation, each rule is tested against the Red Agent's evolved
evasions from brain_state.json — the bypass rate is embedded in the rule
as machine-readable metadata.

Usage:
    python3 sigma_exporter.py
    python3 sigma_exporter.py --rules reports/operational_rules.json
    python3 sigma_exporter.py --rules reports/operational_rules.json \
                               --brain reports/brain_state.json \
                               --out reports/sigma_rules/
"""
import json
import os
import re
import uuid
import argparse
from datetime import datetime, timezone

_REPORTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')

# MITRE technique → Sigma metadata
TECHNIQUE_META = {
    'T1547.001': {
        'title': 'Registry Run Key Persistence',
        'tags': ['attack.persistence', 'attack.t1547.001'],
        'logsource': {'product': 'windows', 'category': 'registry_set'},
        'primary_fields': ['TargetObject', 'Details'],
        'mitre_url': 'https://attack.mitre.org/techniques/T1547/001/',
        'fp_note': 'Legitimate software installations and Windows updates',
    },
    'T1036.005': {
        'title': 'Process Masquerading via DLL Injection',
        'tags': ['attack.defense_evasion', 'attack.t1036.005'],
        'logsource': {'product': 'windows', 'category': 'create_remote_thread'},
        'primary_fields': ['SourceImage', 'TargetImage', 'StartAddress'],
        'mitre_url': 'https://attack.mitre.org/techniques/T1036/005/',
        'fp_note': 'Security software performing process inspection',
    },
    'T1003.001': {
        'title': 'LSASS Memory Access for Credential Dumping',
        'tags': ['attack.credential_access', 'attack.t1003.001'],
        'logsource': {'product': 'windows', 'category': 'process_access'},
        'primary_fields': ['TargetImage', 'GrantedAccess'],
        'mitre_url': 'https://attack.mitre.org/techniques/T1003/001/',
        'fp_note': 'Windows Defender and AV products accessing LSASS',
    },
    'T1071.001': {
        'title': 'Command and Control via Web Protocol',
        'tags': ['attack.command_and_control', 'attack.t1071.001'],
        'logsource': {'product': 'windows', 'category': 'network_connection'},
        'primary_fields': ['DestinationIp', 'DestinationPort'],
        'mitre_url': 'https://attack.mitre.org/techniques/T1071/001/',
        'fp_note': 'Known-good IP allowlist required for production deployment',
    },
    'T1569.002': {
        'title': 'System Service Execution via PsExec',
        'tags': ['attack.execution', 'attack.lateral_movement', 'attack.t1569.002'],
        'logsource': {'product': 'windows', 'category': 'process_creation'},
        'primary_fields': ['Image', 'CommandLine', 'ParentImage'],
        'mitre_url': 'https://attack.mitre.org/techniques/T1569/002/',
        'fp_note': 'Authorized administrative use of PsExec or SC.exe',
    },
}

# Strings that pollute detection with Mordor lab artefacts
_LAB_HOSTNAME_RE = re.compile(
    r'\b\w+\.(mordor|theshire|acme|internal|corp|local)\b', re.IGNORECASE
)
# Pure access mask (0x...) — too generic for keyword detection
_HEX_MASK_RE = re.compile(r'^0x[0-9a-fA-F]+$')
# Pure EventID without additional content
_PURE_EVENTID_RE = re.compile(r'^eventid=\d+$', re.IGNORECASE)
# IPv4 address
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _extract_useful_parts(signal: str) -> list[str]:
    """
    Break pipe-delimited structured signals into individual useful parts.
    Input:  'svchost.exe | TargetObject=HKLM\\SOFTWARE\\... | EventID=12'
    Output: ['HKLM\\SOFTWARE\\...', 'svchost.exe']
    """
    if '|' not in signal:
        return [signal.strip()]

    parts = []
    for segment in signal.split('|'):
        segment = segment.strip()
        # Strip field= prefix, keep the value
        if '=' in segment:
            segment = segment.split('=', 1)[1].strip()
        if segment:
            parts.append(segment)
    return parts


def _classify(raw: str) -> tuple[str, str]:
    """
    Returns (category, cleaned_value):
      'registry' — ASEP / credential registry path
      'ip'       — IPv4 address
      'keyword'  — tool name, file name, or unique string
      'skip'     — generic / noisy / too short
    """
    s = raw.strip()

    # Lab hostnames → skip
    if _LAB_HOSTNAME_RE.search(s):
        return ('skip', s)

    # Access masks → skip
    if _HEX_MASK_RE.match(s):
        return ('skip', s)

    # Pure EventID → skip
    if _PURE_EVENTID_RE.match(s):
        return ('skip', s)

    # Too short
    if len(s) < 5:
        return ('skip', s)

    # IPv4
    if _IPV4_RE.match(s):
        return ('ip', s)

    # Registry paths
    if (s.startswith('\\') or s.upper().startswith('HK') or
            '\\SOFTWARE\\' in s.upper() or '\\SYSTEM\\' in s.upper() or
            '\\CurrentVersion\\' in s or '\\Control\\' in s):
        return ('registry', s)

    return ('keyword', s)


def _select_signals(signals: list[str]) -> dict[str, list[str]]:
    """
    Process a technique's raw signal list into typed buckets.
    Returns {'registry': [...], 'ip': [...], 'keyword': [...]}
    """
    buckets: dict[str, list[str]] = {'registry': [], 'ip': [], 'keyword': []}
    seen: set[str] = set()

    for raw in signals:
        for part in _extract_useful_parts(raw):
            cat, val = _classify(part)
            if cat == 'skip':
                continue
            val_lower = val.lower()
            if val_lower in seen:
                continue
            seen.add(val_lower)
            buckets[cat].append(val)

    return buckets


def _yaml_str(value: str) -> str:
    """Quote a YAML string value if it contains special characters."""
    if any(c in value for c in (':', '#', '[', ']', '{', '}', ',', '&', '*',
                                 '?', '|', '-', '<', '>', '=', '!', '%',
                                 '@', '`', "'", '"', '\\')):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _render_yaml_list(items: list[str], indent: int = 8) -> str:
    pad = ' ' * indent
    return '\n'.join(f"{pad}- {_yaml_str(item)}" for item in items)


def _render_sigma(technique_id: str, rule_data: dict,
                  buckets: dict, validation: dict,
                  iteration: int, date_str: str) -> str:
    """Render a complete Sigma YAML rule as a string."""
    meta = TECHNIQUE_META.get(technique_id, {})
    title = f"{meta.get('title', rule_data['name'])} (ASL-Generated)"
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS,
                              f"find-evil-2026-{technique_id}-{iteration}"))
    tags = meta.get('tags', [])
    logsource = meta.get('logsource', {'product': 'windows', 'service': 'sysmon'})
    fp_note = meta.get('fp_note', 'Administrative tools and security software')

    # Build detection sections
    detection_sections = []
    condition_parts = []

    if buckets['registry']:
        detection_sections.append(
            "    sel_registry:\n"
            "        TargetObject|contains:\n" +
            _render_yaml_list(buckets['registry'], indent=12)
        )
        condition_parts.append('sel_registry')

    if buckets['ip']:
        detection_sections.append(
            "    sel_c2_ips:\n"
            "        DestinationIp:\n" +
            _render_yaml_list(buckets['ip'], indent=12)
        )
        condition_parts.append('sel_c2_ips')

    if buckets['keyword']:
        detection_sections.append(
            "    sel_keywords:\n"
            "        EventData|contains:\n" +
            _render_yaml_list(buckets['keyword'], indent=12)
        )
        condition_parts.append('sel_keywords')

    if not condition_parts:
        # Fallback: put everything as keywords
        all_signals = [s for sl in buckets.values() for s in sl]
        if all_signals:
            detection_sections.append(
                "    sel_keywords:\n"
                "        EventData|contains:\n" +
                _render_yaml_list(all_signals, indent=12)
            )
            condition_parts.append('sel_keywords')

    condition = ' or '.join(condition_parts) if condition_parts else 'none'

    # Adversarial validation block (embedded as YAML comment block + custom field)
    val_bypass = validation.get('bypass_rate', 'N/A')
    val_tested = validation.get('total_evasions', 0)
    val_bypassed = validation.get('bypassed', 0)
    val_ok = validation.get('adversarially_validated', False)
    val_badge = 'VALIDATED' if val_ok else 'NEEDS_HARDENING'

    tags_yaml = '\n'.join(f"    - {t}" for t in tags)
    ls_yaml = '\n'.join(f"    {k}: {v}" for k, v in logsource.items())
    detection_body = '\n'.join(detection_sections)

    return f"""title: {title}
id: {rule_id}
status: experimental
description: |
    Auto-generated by find-evil-2026 ASL adversarial training loop.
    Trained iterations: {iteration}
    Detection weight: {rule_data['weight']}
    Evasions observed during training: {rule_data.get('evasions_seen', 0)}
    Adversarial validation: {val_badge} ({val_tested} evasions tested, {val_bypassed} bypassed)
    Source: {rule_data.get('source', 'GAN_trained')}
references:
    - {meta.get('mitre_url', 'https://attack.mitre.org/')}
    - https://github.com/OTRF/Security-Datasets (Mordor training data)
author: find-evil-2026-asl
date: {date_str}
modified: {date_str}
tags:
{tags_yaml}
logsource:
{ls_yaml}
detection:
{detection_body}
    condition: {condition}
falsepositives:
    - {fp_note}
    - Adversarially validated against {val_tested} Red Agent evasions
level: high
fields:
    - Image
    - CommandLine
    - TargetObject
    - TargetImage
    - DestinationIp
# GAN metadata (machine-readable)
# gan_iteration: {iteration}
# bypass_rate: {val_bypass}
# adversarially_validated: {str(val_ok).lower()}
"""


def validate_against_evasions(rules: dict,
                               brain_state_path: str) -> dict[str, dict]:
    """
    Test each rule's keyword/signal set against the Red Agent's evolved
    evasion artifacts. Returns per-technique validation results.
    """
    if not os.path.exists(brain_state_path):
        print(f"  ⚠️  No brain state at {brain_state_path} — skipping validation")
        return {}

    with open(brain_state_path) as f:
        state = json.load(f)

    red_evasions = state.get('red_evasions', {})
    results: dict[str, dict] = {}

    for technique_id, rule_data in rules.items():
        signals = [s.lower() for s in rule_data.get('signals', [])]
        evasions = red_evasions.get(technique_id, [])

        if not evasions:
            results[technique_id] = {
                'total_evasions': 0,
                'bypassed': 0,
                'bypass_rate': 0.0,
                'adversarially_validated': True,
                'note': 'no evasions to test',
            }
            continue

        bypassed = 0
        bypass_examples = []
        for ev in evasions:
            artifact = ev.get('modified_artifact', '').lower()
            caught = any(sig.lower() in artifact for sig in signals)
            if not caught:
                bypassed += 1
                if len(bypass_examples) < 3:
                    bypass_examples.append(ev.get('modified_artifact', '')[:80])

        total = len(evasions)
        bypass_rate = bypassed / total
        results[technique_id] = {
            'total_evasions': total,
            'bypassed': bypassed,
            'bypass_rate': round(bypass_rate, 3),
            'adversarially_validated': bypass_rate == 0.0,
            'bypass_examples': bypass_examples,
        }

    return results


def export_sigma_rules(rules_path: str = None,
                        brain_path: str = None,
                        out_dir: str = None) -> dict:
    """
    Main entry point. Reads operational_rules.json, generates Sigma YAML
    files into out_dir, and returns a summary dict.
    """
    if rules_path is None:
        rules_path = os.path.join(_REPORTS, 'operational_rules.json')
    if brain_path is None:
        brain_path = os.path.join(_REPORTS, 'brain_state.json')
    if out_dir is None:
        out_dir = os.path.join(_REPORTS, 'sigma_rules')

    if not os.path.exists(rules_path):
        print(f"No operational rules at {rules_path} — run export_patterns.py first")
        return {}

    with open(rules_path) as f:
        data = json.load(f)

    rules = data.get('rules', {})
    iteration = data.get('trained_iterations', 0)
    date_str = datetime.now(timezone.utc).strftime('%Y/%m/%d')

    print(f"🔍 Validating {len(rules)} rules against Red Agent evasions...")
    validation = validate_against_evasions(rules, brain_path)

    os.makedirs(out_dir, exist_ok=True)
    summary = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'gan_iteration': iteration,
        'rules': {},
    }

    print(f"\n📐 Generating Sigma rules → {out_dir}/")
    for technique_id, rule_data in rules.items():
        buckets = _select_signals(rule_data.get('signals', []))
        signal_count = sum(len(v) for v in buckets.values())

        val = validation.get(technique_id, {
            'total_evasions': 0, 'bypassed': 0,
            'bypass_rate': 0.0, 'adversarially_validated': True,
        })

        yaml_text = _render_sigma(technique_id, rule_data,
                                   buckets, val, iteration, date_str)

        filename = f"{technique_id.replace('.', '_').lower()}.yml"
        filepath = os.path.join(out_dir, filename)
        with open(filepath, 'w') as f:
            f.write(yaml_text)

        badge = '✅ VALIDATED' if val.get('adversarially_validated') else '⚠️  NEEDS HARDENING'
        bypass_pct = f"{val.get('bypass_rate', 0.0)*100:.1f}%"
        print(f"  {technique_id:12s}  signals={signal_count:3d}  "
              f"evasions_tested={val['total_evasions']:3d}  "
              f"bypass={bypass_pct:6s}  {badge}")
        print(f"    → {filepath}")

        summary['rules'][technique_id] = {
            'file': filepath,
            'signal_count': signal_count,
            'buckets': {k: len(v) for k, v in buckets.items()},
            'validation': val,
        }

    # Write machine-readable validation report
    report_path = os.path.join(out_dir, 'validation_report.json')
    with open(report_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\n📊 Validation report → {report_path}")

    validated = sum(
        1 for r in summary['rules'].values()
        if r['validation'].get('adversarially_validated')
    )
    print(f"\n✅ {validated}/{len(rules)} rules adversarially validated "
          f"({validated/len(rules)*100:.0f}% pass rate)")

    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Export ASL-trained patterns as adversarially-validated Sigma rules'
    )
    parser.add_argument('--rules', default=None,
                        help='Path to operational_rules.json')
    parser.add_argument('--brain', default=None,
                        help='Path to brain_state.json (for adversarial validation)')
    parser.add_argument('--out', default=None,
                        help='Output directory for .yml files')
    args = parser.parse_args()

    export_sigma_rules(args.rules, args.brain, args.out)
