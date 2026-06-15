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
echo "-- Metrics evals (conditional — requires pipeline run to generate manifest) --"
for gt in evals/ground_truth/*.json; do
  host="$(python3 -c "import json,sys; print(json.load(open('$gt'))['host'])")"
  manifest="reports/${host}-audit-manifest.json"
  if [ -f "$manifest" ]; then
    _run evals/eval_metrics.py "$manifest"
  else
    echo "SKIP [${host}] metrics eval — ${manifest} not found (run pipeline to generate)"
  fi
done

echo ""
echo "-- Submission verification (narrative + components) --"
if python3 evals/verify_submission.py; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "REGRESSION DETECTED — do not merge to main"
  exit 1
fi

echo "All evals passed — branch is clean"
