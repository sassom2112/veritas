#!/usr/bin/env python3
"""
Metrics eval: validates that an audit manifest produced by investigate.py
has the correct structure and a cost within the $0 < cost <= $20 ceiling.

Exits 0 on pass, 1 on failure, 2 on bad args.

Usage:
  python3 evals/eval_metrics.py reports/nfury-audit-manifest.json
"""

from __future__ import annotations

import json
import sys

_REQUIRED_KEYS = [
    'case_id', 'target_host', 'total_cost_usd',
    'total_input_tokens', 'total_output_tokens',
    'execution_duration_ms', 'phases', 'verdicts_summary',
]
_MAX_COST_USD = 20.0


def eval_manifest(manifest_path: str) -> bool:
    try:
        with open(manifest_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"FAIL [metrics] manifest not found: {manifest_path}")
        return False
    except json.JSONDecodeError as exc:
        print(f"FAIL [metrics] malformed JSON in {manifest_path}: {exc}")
        return False

    missing = [k for k in _REQUIRED_KEYS if k not in data]
    if missing:
        print(f"FAIL [metrics] missing required keys: {missing}")
        return False

    cost = data['total_cost_usd']
    if not isinstance(cost, (int, float)):
        print(f"FAIL [metrics] total_cost_usd is not numeric: {cost!r}")
        return False
    if not (0.0 < cost <= _MAX_COST_USD):
        print(f"FAIL [metrics] cost ${cost:.4f} outside valid range (0, ${_MAX_COST_USD:.2f}]")
        return False

    if not isinstance(data['phases'], dict) or not data['phases']:
        print(f"FAIL [metrics] phases is empty or not a dict")
        return False

    host = data.get('target_host', manifest_path)
    print(
        f"PASS [{host}] metrics eval — "
        f"${cost:.4f} total, "
        f"{data['total_input_tokens']}in/{data['total_output_tokens']}out tokens, "
        f"{len(data['phases'])} phases tracked"
    )
    return True


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: eval_metrics.py <manifest.json>")
        return 2
    return 0 if eval_manifest(sys.argv[1]) else 1


if __name__ == '__main__':
    sys.exit(main())
