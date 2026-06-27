#!/usr/bin/env python3
"""
Trajectory eval: verifies that specific techniques used expected tool patterns
across their audit challenge rounds. Catches regressions where a technique
reached the correct verdict via an unexpected (or empty) tool path.

Exits 0 on pass, 1 on any failure.

Usage:
  python3 evals/eval_trajectory.py evals/ground_truth/nfury.json
  python3 evals/eval_trajectory.py evals/ground_truth/nfury.json reports/nfury-auditor-transcript.json
"""

from __future__ import annotations

import json
import sys


def _load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _all_tools(challenges: list[dict]) -> list[str]:
    tools: list[str] = []
    for ch in challenges:
        tools.extend(ch.get("tools_called", []))
    return tools


def eval_trajectory(gt_path: str, report_path: str | None = None) -> bool:
    gt = _load(gt_path)
    checks = gt.get("trajectory_checks", [])
    host = gt["host"]

    if not checks:
        print(f"PASS [{host}] trajectory eval — no checks defined")
        return True

    report = _load(report_path or gt["source_report"])
    index = {entry["finding_id"]: entry for entry in report.get("transcript", [])}
    failures: list[str] = []

    for check in checks:
        tid = check["technique_id"]
        required_any: list[str] = check["required_any"]
        description = check["description"]

        if tid not in index:
            failures.append(f"  {tid}: not found in transcript")
            continue

        tools = _all_tools(index[tid]["challenges"])
        matched = any(
            pattern in tool
            for tool in tools
            for pattern in required_any
        )

        if not matched:
            shown = tools[:4]
            failures.append(
                f"  {tid}: {description}\n"
                f"    required one of {required_any}\n"
                f"    tools called: {shown}"
            )

    if failures:
        print(f"FAIL [{host}] trajectory eval")
        for line in failures:
            print(line)
        return False

    print(f"PASS [{host}] trajectory eval — {len(checks)} checks")
    return True


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: eval_trajectory.py <ground_truth.json> [report.json]")
        return 2
    passed = eval_trajectory(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
