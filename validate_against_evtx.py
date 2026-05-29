"""
Cross-validate VERITAS operational rules against Splunk EVTX-ATTACK-SAMPLES data.

This script runs VERITAS's trained detection rules against a second, independent
dataset — the EVTX-ATTACK-SAMPLES CSV used by the Splunk Agentic IR project.
A rule "detects" if any of its signals match a case-insensitive substring in the
event text of events belonging to that technique's tactic category.

Usage:
    python validate_against_evtx.py [--csv PATH] [--rules PATH] [--out PATH]

Defaults:
    --csv   ../splunk-agentic-ir/data/samples/evtx-attack-samples/evtx_data.csv
    --rules reports/operational_rules.json
    --out   reports/evtx_cross_validation.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Fields to search for signal matches (case-insensitive substring)
_SEARCH_FIELDS = [
    "CommandLine",
    "Image",
    "TargetImage",
    "NewProcessName",
    "ProcessName",
    "TargetObject",
    "TargetFilename",
    "ParentCommandLine",
    "ParentImage",
    "ScriptBlockText",
    "Description",
    "ServiceName",
    "ImageLoaded",
    "SourceImage",
    "Details",
    "ObjectName",
]

# Map VERITAS technique IDs → expected EVTX_Tactic labels (partial match)
_TACTIC_MAP: dict[str, list[str]] = {
    "T1003.001": ["credential", "cred"],
    "T1547.001": ["persistence"],
    "T1036.005": ["defense evasion", "evasion"],
    "T1071.001": ["command and control", "c2"],
    "T1569.002": ["lateral movement", "execution"],
    "T1087.001": ["discovery"],
    "T1059.001": ["execution"],
    "T1548.002": ["privilege escalation"],
    "T1560.001": ["collection"],
    "T1055":     ["defense evasion", "privilege escalation"],
    "T1056.001": ["collection"],
}


def _load_rules(rules_path: Path) -> dict[str, Any]:
    data = json.loads(rules_path.read_text())
    return data["rules"] if "rules" in data else data


def _load_events(csv_path: Path) -> list[dict[str, str]]:
    import csv
    rows: list[dict[str, str]] = []
    with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
    return rows


def _event_text(row: dict[str, str]) -> str:
    parts = [row.get(f, "") or "" for f in _SEARCH_FIELDS]
    return " ".join(parts).lower()


def _tactic_matches(tactic_cell: str, expected: list[str]) -> bool:
    t = tactic_cell.lower()
    return any(e in t for e in expected)


def _signal_matches(signal: str, text: str) -> bool:
    return signal.lower() in text


def _split_signals_by_tier(rule: dict) -> tuple[list[str], list[str]]:
    """Return (asl_trained_signals, forensic_ioc_signals) from a rule dict.

    forensic_ioc signals were extracted from the specific case under investigation
    and added back into the rules.  They are expected to fire on that case and
    nothing else — testing them on an independent dataset is circular.
    Only asl_trained signals reflect genuine generalisation from the Red/Blue loop.
    """
    tagged: list[dict] = rule.get("signals_tagged", [])
    if tagged:
        asl = [t["signal"] for t in tagged if t.get("tier") == "asl_trained"]
        ioc = [t["signal"] for t in tagged if t.get("tier") == "forensic_ioc"]
    else:
        # Fallback: treat all signals as asl_trained if no tier data
        asl = rule.get("signals", [])
        ioc = []
    return asl, ioc


def _check_signals(signals: list[str], on_target: list[dict], off_target: list[dict]) -> dict:
    matched: list[str] = []
    hit_counts: dict[str, int] = {}
    for sig in signals:
        count = sum(1 for e in on_target if _signal_matches(sig, _event_text(e)))
        if count:
            matched.append(sig)
            hit_counts[sig] = count
    fp: list[str] = [s for s in matched
                     if any(_signal_matches(s, _event_text(e)) for e in off_target)]
    return {"matched": matched, "hit_counts": hit_counts, "fp": fp}


def validate(rules: dict, events: list[dict]) -> dict:
    results: dict[str, Any] = {}

    for tid, rule in rules.items():
        name: str = rule.get("name", tid)
        weight: int = rule.get("weight", 50)
        expected_tactics: list[str] = _TACTIC_MAP.get(tid, [])

        asl_signals, ioc_signals = _split_signals_by_tier(rule)

        on_target = [e for e in events if _tactic_matches(e.get("EVTX_Tactic", ""), expected_tactics)] if expected_tactics else events
        off_target = [e for e in events if not _tactic_matches(e.get("EVTX_Tactic", ""), expected_tactics)] if expected_tactics else []

        asl_result = _check_signals(asl_signals, on_target, off_target)
        ioc_result = _check_signals(ioc_signals, on_target, off_target)

        # Detection is only credited when asl_trained signals fire.
        # forensic_ioc signals are case-specific and excluded from the claim.
        detected = len(asl_result["matched"]) > 0
        asl_precision = len(asl_result["matched"]) / max(len(asl_signals), 1)

        results[tid] = {
            "name": name,
            "weight": weight,
            "detected_asl_only": detected,
            "asl_signals": {
                "total": len(asl_signals),
                "matched": asl_result["matched"],
                "hit_counts": asl_result["hit_counts"],
                "fp": asl_result["fp"],
                "precision": round(asl_precision, 3),
            },
            "forensic_ioc_signals": {
                "signals": ioc_signals,
                "note": "case-specific; excluded from cross-dataset claim",
                "matched_on_independent_data": ioc_result["matched"],
            },
            "on_target_events": len(on_target),
            "expected_tactics": expected_tactics,
        }

    detected_count = sum(1 for r in results.values() if r["detected_asl_only"])
    total = len(results)
    # Rules with no asl_trained signals at all can't contribute to the detection rate
    asl_eligible = sum(1 for r in results.values() if r["asl_signals"]["total"] > 0)
    asl_rate = round(detected_count / max(asl_eligible, 1), 3)

    return {
        "summary": {
            "rules_tested": total,
            "asl_eligible_rules": asl_eligible,
            "rules_detected_asl_only": detected_count,
            "detection_rate_asl_only": asl_rate,
            "detection_rate_pct": f"{asl_rate * 100:.1f}%",
            "dataset": "EVTX-ATTACK-SAMPLES (Splunk Agentic IR)",
            "methodology": (
                "Only asl_trained signals (learned via Red/Blue loop on Mordor data) "
                "are counted toward detection. forensic_ioc signals are case-specific "
                "artifacts extracted from the SANS investigation itself and are "
                "excluded — testing them on an independent dataset would be circular."
            ),
        },
        "per_technique": results,
    }


def print_table(report: dict) -> None:
    s = report["summary"]
    print(f"\n{'=' * 66}")
    print(f"  VERITAS Rules × EVTX-ATTACK-SAMPLES Cross-Validation")
    print(f"{'=' * 66}")
    print(f"  Dataset    : {s['dataset']}")
    print(f"  Rules      : {s['rules_tested']} total, {s['asl_eligible_rules']} with asl_trained signals")
    print(f"  Detected   : {s['rules_detected_asl_only']}  ({s['detection_rate_pct']})")
    print(f"  Basis      : asl_trained signals only (forensic_ioc excluded — circular)")
    print(f"{'=' * 66}\n")

    header = f"{'Technique':<14} {'Name':<28} {'Det':>4} {'ASL match':>10} {'IOC sigs':>9}"
    print(header)
    print("-" * len(header))
    for tid, r in report["per_technique"].items():
        det = "YES" if r["detected_asl_only"] else "NO "
        asl = r["asl_signals"]
        asl_str = f"{len(asl['matched'])}/{asl['total']}"
        ioc_count = len(r["forensic_ioc_signals"]["signals"])
        ioc_str = f"{ioc_count} (excl.)" if ioc_count else "—"
        print(f"{tid:<14} {r['name']:<28} {det:>4} {asl_str:>10} {ioc_str:>9}")

    print()
    print("  ASL-matched signals per detected technique:")
    for tid, r in report["per_technique"].items():
        if r["detected_asl_only"]:
            sigs = ", ".join(r["asl_signals"]["matched"][:5])
            print(f"    {tid}: {sigs}")

    excl = [(tid, r) for tid, r in report["per_technique"].items()
            if r["forensic_ioc_signals"]["signals"]]
    if excl:
        print()
        print("  Excluded forensic_ioc signals (case-specific, not tested):")
        for tid, r in excl:
            sigs = ", ".join(r["forensic_ioc_signals"]["signals"])
            print(f"    {tid}: {sigs}")
    print()


def main() -> None:
    here = Path(__file__).parent
    default_csv = here.parent / "splunk-agentic-ir" / "data" / "samples" / "evtx-attack-samples" / "evtx_data.csv"
    default_rules = here / "reports" / "operational_rules.json"
    default_out = here / "reports" / "evtx_cross_validation.json"

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--csv", type=Path, default=default_csv)
    p.add_argument("--rules", type=Path, default=default_rules)
    p.add_argument("--out", type=Path, default=default_out)
    args = p.parse_args()

    for path, name in [(args.csv, "EVTX CSV"), (args.rules, "rules JSON")]:
        if not path.exists():
            print(f"ERROR: {name} not found at {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Loading rules from {args.rules}...")
    rules = _load_rules(args.rules)
    print(f"  {len(rules)} rules loaded")

    print(f"Loading events from {args.csv}...")
    events = _load_events(args.csv)
    print(f"  {len(events):,} events loaded")

    print("Running cross-validation...")
    report = validate(rules, events)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(f"Report saved to {args.out}")

    print_table(report)


if __name__ == "__main__":
    main()
