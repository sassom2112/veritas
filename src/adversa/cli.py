"""VERITAS CLI — human-only approval workflow.

Commands:
  adversa review [case_dir]              List findings with DRAFT/APPROVED status
  adversa approve <case_dir> <finding_id> Password-gate: DRAFT → APPROVED + HMAC ledger
  adversa reject  <case_dir> <finding_id> Password-gate: DRAFT → REJECTED
  adversa verify  <case_dir>             Verify HMAC integrity of all APPROVED findings
  adversa config  --setup-password       Configure approval password
  adversa report  <case_dir>             Re-generate HTML report from case

The approve/reject commands read from /dev/tty — they cannot be called by
an AI agent via Bash. This is structural, not prompt-based.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_CONFIG_PATH = Path.home() / ".adversa" / "config.yaml"


def _get_examiner() -> str:
    env = os.environ.get("VERITAS_EXAMINER", "").strip().lower()
    return env if env else getpass.getuser().strip().lower()


def cmd_review(args: argparse.Namespace) -> None:
    from adversa.case_io import load_findings, load_approval_log

    case_dir = Path(args.case_dir)
    if not case_dir.is_dir():
        print(f"ERROR: case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(case_dir)
    if not findings:
        print(f"No findings in {case_dir}")
        return

    approvals = {r["finding_id"]: r for r in load_approval_log(case_dir)}

    width = 72
    print(f"\n{'─' * width}")
    print(f"  VERITAS Case Review: {case_dir.name}")
    print(f"  {len(findings)} finding(s)")
    print(f"{'─' * width}")

    status_color = {
        "APPROVED": "\033[32m",   # green
        "REJECTED": "\033[31m",   # red
        "DRAFT":    "\033[33m",   # yellow
    }
    reset = "\033[0m"

    for f in findings:
        fid      = f["id"]
        tid      = f.get("technique_id", "")
        name     = f.get("technique_name", "")
        verdict  = f.get("auditor_verdict", "")
        status   = f.get("status", "DRAFT")
        color    = status_color.get(status, "")
        approved = approvals.get(fid, {})
        by_line  = f"  approved_by={approved.get('examiner', '')} at={approved.get('ts', '')[:19]}" if status == "APPROVED" else ""

        verdict_sym = {"CONFIRMED": "✓", "REFUTED": "✗", "INCONCLUSIVE": "?"}.get(verdict, "?")
        print(f"\n  {color}{status:8}{reset}  {fid}")
        print(f"           {verdict_sym} Auditor: {verdict:13}  [{tid}] {name}")
        if by_line:
            print(f"  {by_line}")

    draft_count = sum(1 for f in findings if f.get("status") == "DRAFT")
    if draft_count:
        print(f"\n{'─' * width}")
        print(f"  {draft_count} finding(s) pending approval.")
        print(f"  To approve:  adversa approve {case_dir} <finding_id>")
        print(f"  To reject:   adversa reject  {case_dir} <finding_id>")
    print(f"{'─' * width}\n")


def cmd_approve(args: argparse.Namespace) -> None:
    _approve_or_reject(args, action="APPROVED")


def cmd_reject(args: argparse.Namespace) -> None:
    _approve_or_reject(args, action="REJECTED")


def _approve_or_reject(args: argparse.Namespace, action: str) -> None:
    from adversa.approval_auth import require_confirmation, get_analyst_salt
    from adversa.case_io import (
        load_findings, save_findings, write_approval_log,
        compute_content_hash, CaseError,
    )
    from adversa.verification import (
        derive_hmac_key, compute_hmac, write_ledger_entry,
    )

    case_dir   = Path(args.case_dir)
    finding_id = args.finding_id
    examiner   = _get_examiner()

    if not case_dir.is_dir():
        print(f"ERROR: case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    findings = load_findings(case_dir)
    target   = next((f for f in findings if f["id"] == finding_id), None)
    if target is None:
        print(f"ERROR: finding '{finding_id}' not found in {case_dir}", file=sys.stderr)
        sys.exit(1)

    if target.get("status") != "DRAFT":
        print(
            f"Finding '{finding_id}' is already {target['status']} — nothing to do.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Display the finding for review before asking for password
    tid     = target.get("technique_id", "")
    name    = target.get("technique_name", "")
    verdict = target.get("auditor_verdict", "")
    signals = target.get("triage_signals", [])
    print(f"\n  Finding:  {finding_id}")
    print(f"  [{tid}] {name}")
    print(f"  Auditor verdict:  {verdict}")
    print(f"  Triage signals:   {signals}")
    print(f"  Action:           {action}")
    print()

    # Password gate — reads from /dev/tty, cannot be called by AI
    _mode, password = require_confirmation(_CONFIG_PATH, examiner)

    # Get salt for HMAC derivation
    try:
        salt = get_analyst_salt(_CONFIG_PATH, examiner)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Update finding status
    now = datetime.now(timezone.utc).isoformat()
    target["status"]      = action
    target["modified_at"] = now
    if action == "APPROVED":
        target["approved_at"] = now
        target["approved_by"] = examiner
    else:
        target["rejected_at"] = now
        target["rejected_by"] = examiner

    target["content_hash"] = compute_content_hash(target)
    save_findings(case_dir, findings)

    # Write approval audit log
    write_approval_log(case_dir, finding_id, action, examiner)

    # Write HMAC to verification ledger (approved findings only)
    if action == "APPROVED":
        derived_key      = derive_hmac_key(password, salt)
        content_snapshot = json.dumps(
            {k: v for k, v in target.items() if k not in {"content_hash", "modified_at"}},
            sort_keys=True, default=str,
        )
        sig = compute_hmac(derived_key, content_snapshot)
        write_ledger_entry(case_dir.name, {
            "finding_id":       finding_id,
            "content_snapshot": content_snapshot,
            "hmac":             sig,
            "approved_by":      examiner,
            "approved_at":      now,
            "case_id":          case_dir.name,
        })
        print(f"  APPROVED — HMAC signed in /var/lib/adversa/verification/{case_dir.name}.jsonl")
    else:
        print(f"  REJECTED — logged to {case_dir}/approvals.jsonl")


def cmd_verify(args: argparse.Namespace) -> None:
    from adversa.approval_auth import has_password, get_analyst_salt
    from adversa.verification import verify_items

    case_dir = Path(args.case_dir)
    examiner = _get_examiner()

    if not case_dir.is_dir():
        print(f"ERROR: case directory not found: {case_dir}", file=sys.stderr)
        sys.exit(1)

    if not has_password(_CONFIG_PATH, examiner):
        print("No password configured — cannot verify HMAC signatures.", file=sys.stderr)
        sys.exit(1)

    from adversa.approval_auth import getpass_prompt
    password = getpass_prompt("Enter password to verify signatures: ")

    try:
        salt = get_analyst_salt(_CONFIG_PATH, examiner)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    results = verify_items(case_dir.name, password, salt, examiner)
    if not results:
        print(f"No approved findings in verification ledger for {case_dir.name}")
        return

    all_ok = True
    for r in results:
        status = "OK      " if r["verified"] else "TAMPERED"
        color  = "\033[32m" if r["verified"] else "\033[31m"
        reset  = "\033[0m"
        print(f"  {color}{status}{reset}  {r['finding_id']}")
        if not r["verified"]:
            all_ok = False

    if all_ok:
        print(f"\n  All {len(results)} finding(s) verified — HMAC signatures intact.")
    else:
        print(f"\n  WARNING: tampered finding(s) detected.")
        sys.exit(2)


def cmd_config(args: argparse.Namespace) -> None:
    from adversa.approval_auth import setup_password

    examiner = _get_examiner()
    if args.setup_password:
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        setup_password(_CONFIG_PATH, examiner)
    else:
        print(f"  Examiner: {examiner}")
        print(f"  Config:   {_CONFIG_PATH}")
        print(f"  Cases:    {Path.home() / 'adversa-cases'}")
        print(f"\n  adversa config --setup-password   Configure approval password")


def cmd_report(args: argparse.Namespace) -> None:
    """Re-generate HTML report from case directory, annotating approval status."""
    case_dir = Path(args.case_dir)
    host     = case_dir.name

    # Locate reports dir relative to the adversa repo
    reports_dir = case_dir / "reports"
    if not reports_dir.is_dir():
        # Fall back to the default reports/ directory
        reports_dir = Path(__file__).resolve().parents[3] / "reports"

    if not reports_dir.is_dir():
        print(f"ERROR: reports directory not found. Run investigate.py first.", file=sys.stderr)
        sys.exit(1)

    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "custom-agent"))
    try:
        from html_report import generate_report
    except ImportError as e:
        print(f"ERROR: could not import html_report: {e}", file=sys.stderr)
        sys.exit(1)

    path = generate_report(host, str(reports_dir))
    print(f"Report: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adversa",
        description="VERITAS — forensic investigation approval CLI",
    )
    sub = parser.add_subparsers(dest="command", help="Commands")

    # review
    p_review = sub.add_parser("review", help="List findings with approval status")
    p_review.add_argument("case_dir", help="Case directory (e.g. ~/adversa-cases/nfury)")
    p_review.set_defaults(func=cmd_review)

    # approve
    p_approve = sub.add_parser("approve", help="Approve a DRAFT finding (password required)")
    p_approve.add_argument("case_dir",   help="Case directory")
    p_approve.add_argument("finding_id", help="Finding ID (e.g. F-analyst-T1003.001)")
    p_approve.set_defaults(func=cmd_approve)

    # reject
    p_reject = sub.add_parser("reject", help="Reject a DRAFT finding (password required)")
    p_reject.add_argument("case_dir",   help="Case directory")
    p_reject.add_argument("finding_id", help="Finding ID")
    p_reject.set_defaults(func=cmd_reject)

    # verify
    p_verify = sub.add_parser("verify", help="Verify HMAC integrity of APPROVED findings")
    p_verify.add_argument("case_dir", help="Case directory")
    p_verify.set_defaults(func=cmd_verify)

    # config
    p_config = sub.add_parser("config", help="Configure VERITAS settings")
    p_config.add_argument("--setup-password", action="store_true",
                          help="Set up approval password")
    p_config.set_defaults(func=cmd_config)

    # report
    p_report = sub.add_parser("report", help="Re-generate HTML report")
    p_report.add_argument("case_dir", help="Case directory")
    p_report.set_defaults(func=cmd_report)

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
