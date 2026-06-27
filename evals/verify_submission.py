#!/usr/bin/env python3
"""
Sprint 5 completeness gate — three-layer narrative + 8-component audit.

Checks:
  Layer 1: Markdown (*.md)      — no stale agent names / framing
  Layer 2: TeX (docs/*.tex)     — same check
  Layer 3: Python diagrams       — gen_guardrails.py clean
  Layer 4: Images                — adversa-*.png present and non-zero
  Layer 5: 8 required components — all required files exist

Exits 0 on full pass, 1 on any failure.
Run: python3 evals/verify_submission.py
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

_STALE_TERMS = [
    'Triage Agent',
    'triage agent',
    'two-player game',
    'Two Agents',
    'Cynic',
    'Optimist',
    'fast_triage',
    'controller host',
    'controller:',
]

_EXCLUDE_PATHS = {
    'evals/verify_submission.py',   # this file
    'HANDOFF.md',                   # may reference old names for context
    'docs/adversa-guardrails.log',
    'docs/adversa-guardrails.aux',
    'fast-triage/',                 # legitimate deprecated path, still functional
    'find_evil.py',                 # cmd_triage() calls fast_triage.py by filename — functional, not narrative
}

_REQUIRED_FILES = [
    'LICENSE',
    'README.md',
    'AGENTS.md',
    'SUBMISSION.md',
    'DATASET.md',
    'ACCURACY.md',
    'docs/adversa-architecture.png',
    'docs/adversa-guardrails.png',
]

_REQUIRED_IMAGES = [
    'docs/adversa-architecture.png',
    'docs/adversa-guardrails.png',
]


def _rel(path: str) -> str:
    return os.path.relpath(path, _ROOT)


def check_stale_terms() -> list[str]:
    failures: list[str] = []
    for dirpath, _dirs, files in os.walk(_ROOT):
        _dirs[:] = [d for d in _dirs if d not in ('.git', 'venv', '__pycache__', 'node_modules')]
        for fname in files:
            if not (fname.endswith('.md') or fname.endswith('.tex') or
                    fname.endswith('.py') or fname.endswith('.sh')):
                continue
            path = os.path.join(dirpath, fname)
            rel  = _rel(path)
            if any(ex in rel for ex in _EXCLUDE_PATHS):
                continue
            try:
                content = open(path, encoding='utf-8', errors='ignore').read()
            except OSError:
                continue
            for term in _STALE_TERMS:
                if term in content:
                    failures.append(f"  LEAK  {rel}  →  '{term}'")
    return failures


def check_required_files() -> list[str]:
    failures: list[str] = []
    for rel in _REQUIRED_FILES:
        path = os.path.join(_ROOT, rel)
        if not os.path.isfile(path):
            failures.append(f"  MISSING  {rel}")
    return failures


def check_images() -> list[str]:
    failures: list[str] = []
    for rel in _REQUIRED_IMAGES:
        path = os.path.join(_ROOT, rel)
        if not os.path.isfile(path):
            failures.append(f"  MISSING IMAGE  {rel}")
        elif os.path.getsize(path) < 10_000:
            failures.append(f"  SUSPICIOUSLY SMALL IMAGE  {rel}  ({os.path.getsize(path)} bytes)")
    return failures


def main() -> int:
    print("=== VERITAS Submission Verification ===\n")

    all_failures: list[str] = []

    print("-- Layer 1+2+3: Stale narrative scan (md / tex / py / sh) --")
    leaks = check_stale_terms()
    if leaks:
        print('\n'.join(leaks))
        all_failures.extend(leaks)
    else:
        print("  CLEAN — no stale agent names or framing found")

    print("\n-- Layer 4: Images present and non-trivial --")
    img_fails = check_images()
    if img_fails:
        print('\n'.join(img_fails))
        all_failures.extend(img_fails)
    else:
        for rel in _REQUIRED_IMAGES:
            path = os.path.join(_ROOT, rel)
            print(f"  OK  {rel}  ({os.path.getsize(path):,} bytes)")

    print("\n-- Layer 5: 8 required submission components --")
    file_fails = check_required_files()
    if file_fails:
        print('\n'.join(file_fails))
        all_failures.extend(file_fails)
    else:
        for rel in _REQUIRED_FILES:
            print(f"  OK  {rel}")

    print()
    if all_failures:
        print(f"FAILED — {len(all_failures)} issue(s) found. Fix before submitting.")
        return 1
    print("PASSED — all layers clean, all components present.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
