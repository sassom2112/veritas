#!/usr/bin/env python3
"""
Output eval: compares final verdicts in a VERITAS audit transcript against
ground truth. Exits 0 on match, 1 on any regression.

Usage:
  python3 evals/eval_output.py evals/ground_truth/nfury.json
  python3 evals/eval_output.py evals/ground_truth/nfury.json reports/nfury-auditor-transcript.json
"""

from __future__ import annotations

import json
import sys


def _load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def eval_host(gt_path: str, report_path: str | None = None) -> bool:
    gt = _load(gt_path)
    expected = gt["expected"]
    report = _load(report_path or gt["source_report"])
    host = gt["host"]
    failures: list[str] = []

    pairs = [
        ("confirmed", "confirmed_findings"),
        ("refuted", "refuted_findings"),
        ("inconclusive", "inconclusive_findings"),
    ]
    for gt_key, report_key in pairs:
        want = set(expected.get(gt_key, []))
        got = set(report.get(report_key, []))
        missing = want - got
        extra = got - want
        if missing:
            failures.append(f"  {gt_key.upper()} missing:     {sorted(missing)}")
        if extra:
            failures.append(f"  {gt_key.upper()} unexpected:  {sorted(extra)}")

    if failures:
        print(f"FAIL [{host}] output eval")
        for line in failures:
            print(line)
        return False

    c = len(set(expected["confirmed"]))
    r = len(set(expected["refuted"]))
    i = len(set(expected.get("inconclusive", [])))
    print(f"PASS [{host}] output eval — {c} confirmed, {r} refuted, {i} inconclusive")
    return True


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: eval_output.py <ground_truth.json> [report.json]")
        return 2
    passed = eval_host(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
