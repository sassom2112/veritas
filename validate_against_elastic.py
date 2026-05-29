"""
Cross-validate VERITAS operational rules against Elastic IR Agent's ECS-formatted
EVTX-ATTACK-SAMPLES dataset (ir-agent/data/processed/evtx_events.jsonl).

Same methodology as validate_against_evtx.py:
  - Only asl_trained signals are counted toward detection.
  - forensic_ioc signals are excluded — they were extracted from the SANS case
    and testing them on independent data would be circular.

Elastic data uses ECS field names: process.name, process.command_line,
process.parent.name, host.name, threat.tactic.name, threat.technique.id.

Usage:
    python validate_against_elastic.py [--jsonl PATH] [--rules PATH] [--out PATH]

Defaults:
    --jsonl  ../ir-agent/data/processed/evtx_events.jsonl
    --rules  reports/operational_rules.json
    --out    reports/elastic_cross_validation.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# ECS fields to concatenate for signal matching
_SEARCH_FIELDS = [
    "process.name",
    "process.command_line",
    "process.parent.name",
    "host.name",
    "event.action",
    "winlog.event_data.ServiceName",
]

# VERITAS technique → Elastic threat.tactic.name values
_TACTIC_MAP: dict[str, list[str]] = {
    "T1003.001": ["credential access"],
    "T1547.001": ["persistence"],
    "T1036.005": ["defense evasion"],
    "T1071.001": [],           # not in Elastic dataset
    "T1569.002": ["lateral movement", "execution"],
    "T1087.001": [],           # no discovery events in this dataset
    "T1059.001": ["execution"],
    "T1548.002": ["defense evasion", "privilege escalation"],
    "T1560.001": [],           # no collection events in this dataset
    "T1055":     ["defense evasion"],
    "T1056.001": [],           # not in Elastic dataset
}


def _load_rules(rules_path: Path) -> dict[str, Any]:
    data = json.loads(rules_path.read_text())
    return data["rules"] if "rules" in data else data


def _load_events(jsonl_path: Path) -> list[dict]:
    events = []
    with jsonl_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _get_nested(obj: dict, dotted_key: str) -> str:
    """Traverse a.b.c style key into a nested dict."""
    parts = dotted_key.split(".")
    v = obj
    for p in parts:
        if not isinstance(v, dict):
            return ""
        v = v.get(p, "")
    return str(v) if v else ""


def _event_text(event: dict) -> str:
    parts = [_get_nested(event, f) for f in _SEARCH_FIELDS]
    return " ".join(p for p in parts if p).lower()


def _event_tactic(event: dict) -> str:
    return (_get_nested(event, "threat.tactic.name") or "").lower()


def _tactic_matches(event_tactic: str, expected: list[str]) -> bool:
    return any(e in event_tactic for e in expected)


def _signal_matches(signal: str, text: str) -> bool:
    return signal.lower() in text


def _split_signals(rule: dict) -> tuple[list[str], list[str]]:
    tagged = rule.get("signals_tagged", [])
    if tagged:
        asl = [t["signal"] for t in tagged if t.get("tier") == "asl_trained"]
        ioc = [t["signal"] for t in tagged if t.get("tier") == "forensic_ioc"]
    else:
        asl = rule.get("signals", [])
        ioc = []
    return asl, ioc


def _check_signals(signals: list[str], on_target: list[dict],
                   off_target: list[dict]) -> dict:
    matched: list[str] = []
    hit_counts: dict[str, int] = {}
    for sig in signals:
        count = sum(1 for e in on_target if _signal_matches(sig, _event_text(e)))
        if count:
            matched.append(sig)
            hit_counts[sig] = count
    fp = [s for s in matched
          if any(_signal_matches(s, _event_text(e)) for e in off_target)]
    return {"matched": matched, "hit_counts": hit_counts, "fp": fp}


def validate(rules: dict, events: list[dict]) -> dict:
    results: dict[str, Any] = {}

    for tid, rule in rules.items():
        name: str = rule.get("name", tid)
        weight: int = rule.get("weight", 50)
        expected_tactics: list[str] = _TACTIC_MAP.get(tid, [])

        asl_signals, ioc_signals = _split_signals(rule)

        if expected_tactics:
            on_target  = [e for e in events if _tactic_matches(_event_tactic(e), expected_tactics)]
            off_target = [e for e in events if not _tactic_matches(_event_tactic(e), expected_tactics)]
        else:
            # Technique not represented in this dataset — skip detection
            on_target, off_target = [], list(events)

        asl_result = _check_signals(asl_signals, on_target, off_target)
        ioc_result = _check_signals(ioc_signals, on_target, off_target)

        detected = len(asl_result["matched"]) > 0 and bool(expected_tactics)
        asl_prec = len(asl_result["matched"]) / max(len(asl_signals), 1)

        results[tid] = {
            "name": name,
            "weight": weight,
            "in_dataset": bool(expected_tactics),
            "detected_asl_only": detected,
            "asl_signals": {
                "total": len(asl_signals),
                "matched": asl_result["matched"],
                "hit_counts": asl_result["hit_counts"],
                "fp": asl_result["fp"],
                "precision": round(asl_prec, 3),
            },
            "forensic_ioc_signals": {
                "signals": ioc_signals,
                "note": "case-specific; excluded from cross-dataset claim",
            },
            "on_target_events": len(on_target),
            "expected_tactics": expected_tactics,
        }

    in_dataset = [r for r in results.values() if r["in_dataset"] and r["asl_signals"]["total"] > 0]
    detected_count = sum(1 for r in in_dataset if r["detected_asl_only"])
    asl_rate = round(detected_count / max(len(in_dataset), 1), 3)

    tactic_coverage = {}
    for e in events:
        tac = _event_tactic(e) or "unknown"
        tactic_coverage[tac] = tactic_coverage.get(tac, 0) + 1

    return {
        "summary": {
            "rules_tested": len(results),
            "rules_in_dataset": len(in_dataset),
            "rules_detected_asl_only": detected_count,
            "detection_rate_asl_only": asl_rate,
            "detection_rate_pct": f"{asl_rate * 100:.1f}%",
            "total_events": len(events),
            "dataset": "Elastic IR Agent — EVTX-ATTACK-SAMPLES (evtx_events.jsonl)",
            "tactic_distribution": tactic_coverage,
            "methodology": (
                "Only asl_trained signals counted. forensic_ioc signals excluded — circular. "
                "Rules whose technique has no matching tactic in this dataset are excluded "
                "from the rate (marked in_dataset=false)."
            ),
        },
        "per_technique": results,
    }


def print_table(report: dict) -> None:
    s = report["summary"]
    print(f"\n{'=' * 70}")
    print(f"  VERITAS Rules × Elastic IR Agent EVTX Data — Cross-Validation")
    print(f"{'=' * 70}")
    print(f"  Dataset  : {s['dataset']}")
    print(f"  Events   : {s['total_events']:,}")
    print(f"  Rules    : {s['rules_tested']} total, {s['rules_in_dataset']} represented in dataset")
    print(f"  Detected : {s['rules_detected_asl_only']}  ({s['detection_rate_pct']})")
    print(f"  Basis    : asl_trained signals only (forensic_ioc excluded — circular)")
    print(f"{'=' * 70}\n")

    header = f"{'Technique':<14} {'Name':<30} {'In DS':>5} {'Det':>4} {'ASL':>10} {'IOC excl':>9}"
    print(header)
    print("-" * len(header))
    for tid, r in report["per_technique"].items():
        in_ds = "YES" if r["in_dataset"] else "NO "
        det   = "YES" if r["detected_asl_only"] else ("—  " if not r["in_dataset"] else "NO ")
        asl   = r["asl_signals"]
        asl_s = f"{len(asl['matched'])}/{asl['total']}"
        ioc_c = len(r["forensic_ioc_signals"]["signals"])
        ioc_s = f"{ioc_c} (excl.)" if ioc_c else "—"
        print(f"{tid:<14} {r['name']:<30} {in_ds:>5} {det:>4} {asl_s:>10} {ioc_s:>9}")

    print()
    print("  ASL-matched signals (detected techniques only):")
    for tid, r in report["per_technique"].items():
        if r["detected_asl_only"]:
            sigs = ", ".join(r["asl_signals"]["matched"][:5])
            print(f"    {tid}: {sigs}")

    excl = [(t, r) for t, r in report["per_technique"].items()
            if r["forensic_ioc_signals"]["signals"]]
    if excl:
        print()
        print("  Excluded forensic_ioc signals (case-specific):")
        for tid, r in excl:
            sigs = ", ".join(r["forensic_ioc_signals"]["signals"])
            print(f"    {tid}: {sigs}")
    print()


def main() -> None:
    here = Path(__file__).parent
    default_jsonl = here.parent / "ir-agent" / "data" / "processed" / "evtx_events.jsonl"
    default_rules = here / "reports" / "operational_rules.json"
    default_out   = here / "reports" / "elastic_cross_validation.json"

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--jsonl",  type=Path, default=default_jsonl)
    p.add_argument("--rules",  type=Path, default=default_rules)
    p.add_argument("--out",    type=Path, default=default_out)
    args = p.parse_args()

    for path, name in [(args.jsonl, "Elastic JSONL"), (args.rules, "rules JSON")]:
        if not path.exists():
            print(f"ERROR: {name} not found at {path}", file=sys.stderr)
            sys.exit(1)

    print(f"Loading rules from {args.rules}...")
    rules = _load_rules(args.rules)
    print(f"  {len(rules)} rules loaded")

    print(f"Loading events from {args.jsonl}...")
    events = _load_events(args.jsonl)
    print(f"  {len(events):,} events loaded")

    print("Running cross-validation...")
    report = validate(rules, events)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(f"Report saved to {args.out}")

    print_table(report)


if __name__ == "__main__":
    main()
