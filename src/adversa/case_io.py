"""Case file I/O for VERITAS investigations.

Creates and manages the case directory structure:
  ~/adversa-cases/{host}/
    findings.json       — DRAFT/APPROVED findings (chmod 444 after write)
    approvals.jsonl     — append-only approval audit trail (chmod 444)
    audit_log.jsonl     — symlink to reports/{host}/audit_log.jsonl
    verification.jsonl  — copied from /var/lib/adversa/verification/ on close

Ported from Valhuntir (AppliedIR/Valhuntir) — MIT License.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")

DEFAULT_CASES_DIR = str(Path.home() / "adversa-cases")

HASH_EXCLUDE_KEYS = {
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "content_hash",
    "modified_at",
}


class CaseError(Exception):
    pass


def _validate_case_id(case_id: str) -> None:
    if not case_id:
        raise CaseError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise CaseError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    if not examiner or not _EXAMINER_RE.match(examiner):
        raise CaseError(f"Invalid examiner slug: {examiner!r}")


def _atomic_write(path: Path, content: str) -> None:
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _protected_write(path: Path, content: str) -> None:
    """Atomic write then chmod 444 — speed bump against accidental LLM modification."""
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass
    _atomic_write(path, content)
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass


def get_examiner() -> str:
    env = os.environ.get("VERITAS_EXAMINER", "").strip().lower()
    if env:
        _validate_examiner(env)
        return env
    import getpass
    fallback = getpass.getuser().strip().lower()
    try:
        _validate_examiner(fallback)
        return fallback
    except CaseError:
        return "analyst"


def init_case(host: str, cases_dir: str | None = None) -> Path:
    """Create or open the case directory for a host. Returns Path."""
    _validate_case_id(host)
    base = Path(cases_dir or os.environ.get("VERITAS_CASES_DIR", DEFAULT_CASES_DIR))
    case_dir = base / host
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "audit").mkdir(exist_ok=True)
    return case_dir


def load_findings(case_dir: Path) -> list[dict]:
    f = case_dir / "findings.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except json.JSONDecodeError:
        return []


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    _protected_write(
        case_dir / "findings.json",
        json.dumps(findings, indent=2, default=str),
    )


def compute_content_hash(item: dict) -> str:
    hashable = {k: v for k, v in item.items() if k not in HASH_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def write_findings_from_audit(
    case_dir: Path,
    host: str,
    confirmed: list[str],
    inconclusive: list[str],
    refuted: list[str],
    transcript: list[dict],
    examiner: str,
) -> list[dict]:
    """Write auditor results to findings.json as DRAFT. Returns the finding list."""
    existing = {f["id"]: f for f in load_findings(case_dir)}
    now = datetime.now(timezone.utc).isoformat()

    findings = []
    for entry in transcript:
        tid = entry["finding_id"]
        verdict = entry["final_verdict"]
        fid = f"F-{examiner}-{tid}"

        finding = {
            "id": fid,
            "technique_id": tid,
            "technique_name": entry.get("finding_name", tid),
            "status": "DRAFT",
            "auditor_verdict": verdict,
            "triage_signals": entry.get("triage_signals", []),
            "triage_weight": entry.get("triage_weight", 0),
            "convergence_reason": entry.get("convergence_reason", ""),
            "auditor_rounds": len(entry.get("challenges", [])),
            "source": entry.get("source", "disk"),
            "host": host,
            "staged": now,
            "modified_at": now,
            "examiner": examiner,
            "content_hash": "",
        }
        finding["content_hash"] = compute_content_hash(finding)

        # Preserve APPROVED status — never overwrite a human decision
        if fid in existing and existing[fid].get("status") == "APPROVED":
            findings.append(existing[fid])
        else:
            findings.append(finding)

    save_findings(case_dir, findings)
    return findings


def write_approval_log(
    case_dir: Path,
    finding_id: str,
    action: str,
    examiner: str,
    reason: str = "",
) -> bool:
    log_file = case_dir / "approvals.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding_id,
        "action": action,
        "examiner": examiner,
    }
    if reason:
        entry["reason"] = reason
    try:
        if log_file.exists():
            os.chmod(log_file, 0o644)
    except OSError:
        pass
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        print(f"WARNING: Failed to write approval log: {log_file}", file=sys.stderr)
        return False
    try:
        os.chmod(log_file, 0o444)
    except OSError:
        pass
    return True


def load_approval_log(case_dir: Path) -> list[dict]:
    log_file = case_dir / "approvals.jsonl"
    if not log_file.exists():
        return []
    entries = []
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def verify_approval_integrity(case_dir: Path) -> list[dict]:
    """Cross-reference findings.json against approvals.jsonl content hashes."""
    findings = load_findings(case_dir)
    approvals = load_approval_log(case_dir)
    last_approval = {r["finding_id"]: r for r in approvals}

    results = []
    for f in findings:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f["id"]
        record = last_approval.get(fid)

        if status == "DRAFT":
            result["verification"] = "draft"
        elif record and record["action"] == status:
            recomputed = compute_content_hash(f)
            stored = f.get("content_hash", "")
            if stored and recomputed != stored:
                result["verification"] = "tampered"
            elif stored:
                result["verification"] = "confirmed"
            else:
                result["verification"] = "unverified"
        else:
            result["verification"] = "no_approval_record"
        results.append(result)
    return results
