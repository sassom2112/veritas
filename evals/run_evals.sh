#!/usr/bin/env bash
# Sprint 2 regression gate.
# Run before merging future/cross-layer-verification to main.
# Exits 1 if any eval fails.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0
FAIL=0

_run() {
  local script="$1" gt="$2"
  if python3 "$script" "$gt"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
}

echo "=== VERITAS Eval Suite ==="
echo ""

echo "-- Output evals --"
for gt in evals/ground_truth/*.json; do
  _run evals/eval_output.py "$gt"
done

echo ""
echo "-- Trajectory evals --"
for gt in evals/ground_truth/*.json; do
  _run evals/eval_trajectory.py "$gt"
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "REGRESSION DETECTED — do not merge to main"
  exit 1
fi

echo "All evals passed — branch is clean"
