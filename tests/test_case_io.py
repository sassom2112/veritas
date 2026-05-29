"""Tests for VERITAS case I/O module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adversa.case_io import (
    CaseError,
    compute_content_hash,
    init_case,
    load_approval_log,
    load_findings,
    save_findings,
    verify_approval_integrity,
    write_approval_log,
    write_findings_from_audit,
)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("VERITAS_EXAMINER", "analyst")
    d = tmp_path / "nfury"
    d.mkdir()
    (d / "audit").mkdir()
    return d


_SAMPLE_TRANSCRIPT = [
    {
        "finding_id":        "T1003.001",
        "finding_name":      "OS Credential Dumping: LSASS Memory",
        "final_verdict":     "CONFIRMED",
        "triage_signals":    ["lsass.dmp", "mimikatz.exe"],
        "triage_weight":     50,
        "convergence_reason":"positive_evidence_round_1",
        "challenges":        [{"round": 1, "verdict": "CONFIRMED"}],
        "source":            "disk",
    },
    {
        "finding_id":        "T1569.002",
        "finding_name":      "System Services: Service Execution (PsExec)",
        "final_verdict":     "CONFIRMED",
        "triage_signals":    ["PSEXESVC.EXE"],
        "triage_weight":     40,
        "convergence_reason":"positive_evidence_round_1",
        "challenges":        [{"round": 1, "verdict": "CONFIRMED"}],
        "source":            "disk",
    },
    {
        "finding_id":        "T1547.001",
        "finding_name":      "Registry Run Key",
        "final_verdict":     "REFUTED",
        "triage_signals":    ["RunKey_suspect"],
        "triage_weight":     30,
        "convergence_reason":"contradiction_round_1",
        "challenges":        [{"round": 1, "verdict": "REFUTED"}],
        "source":            "disk",
    },
]


class TestInitCase:
    def test_creates_directory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VERITAS_CASES_DIR", str(tmp_path))
        d = init_case("nfury")
        assert d.is_dir()
        assert (d / "audit").is_dir()

    def test_rejects_path_traversal(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VERITAS_CASES_DIR", str(tmp_path))
        with pytest.raises(CaseError):
            init_case("../evil")

    def test_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VERITAS_CASES_DIR", str(tmp_path))
        init_case("nfury")
        init_case("nfury")   # second call must not raise


class TestFindingsIO:
    def test_load_empty(self, case_dir):
        assert load_findings(case_dir) == []

    def test_save_and_load_roundtrip(self, case_dir):
        findings = [{"id": "F-analyst-T1003.001", "status": "DRAFT", "technique_id": "T1003.001"}]
        save_findings(case_dir, findings)
        loaded = load_findings(case_dir)
        assert len(loaded) == 1
        assert loaded[0]["id"] == "F-analyst-T1003.001"

    def test_findings_file_is_readonly(self, case_dir):
        save_findings(case_dir, [{"id": "F-001", "status": "DRAFT"}])
        path = case_dir / "findings.json"
        mode = oct(path.stat().st_mode)[-3:]
        assert mode == "444"


class TestWriteFindingsFromAudit:
    def test_creates_one_finding_per_technique(self, case_dir):
        findings = write_findings_from_audit(
            case_dir, "nfury",
            confirmed=["T1003.001", "T1569.002"],
            inconclusive=[],
            refuted=["T1547.001"],
            transcript=_SAMPLE_TRANSCRIPT,
            examiner="analyst",
        )
        assert len(findings) == 3

    def test_all_findings_start_as_draft(self, case_dir):
        write_findings_from_audit(
            case_dir, "nfury",
            confirmed=["T1003.001", "T1569.002"],
            inconclusive=[],
            refuted=["T1547.001"],
            transcript=_SAMPLE_TRANSCRIPT,
            examiner="analyst",
        )
        for f in load_findings(case_dir):
            assert f["status"] == "DRAFT"

    def test_approved_finding_is_preserved(self, case_dir):
        # Write findings, then manually approve one
        write_findings_from_audit(
            case_dir, "nfury",
            confirmed=["T1003.001", "T1569.002"],
            inconclusive=[],
            refuted=["T1547.001"],
            transcript=_SAMPLE_TRANSCRIPT,
            examiner="analyst",
        )
        findings = load_findings(case_dir)
        findings[0]["status"] = "APPROVED"
        findings[0]["approved_by"] = "analyst"
        save_findings(case_dir, findings)

        # Re-run audit (simulate second run)
        write_findings_from_audit(
            case_dir, "nfury",
            confirmed=["T1003.001", "T1569.002"],
            inconclusive=[],
            refuted=["T1547.001"],
            transcript=_SAMPLE_TRANSCRIPT,
            examiner="analyst",
        )
        loaded = load_findings(case_dir)
        approved = next(f for f in loaded if f["id"] == "F-analyst-T1003.001")
        assert approved["status"] == "APPROVED"  # must not be overwritten


class TestApprovalLog:
    def test_write_and_read_approval(self, case_dir):
        write_approval_log(case_dir, "F-analyst-T1003.001", "APPROVED", "analyst")
        log = load_approval_log(case_dir)
        assert len(log) == 1
        assert log[0]["action"] == "APPROVED"
        assert log[0]["finding_id"] == "F-analyst-T1003.001"

    def test_approval_log_is_append_only(self, case_dir):
        write_approval_log(case_dir, "F-analyst-T1003.001", "APPROVED", "analyst")
        write_approval_log(case_dir, "F-analyst-T1569.002", "APPROVED", "analyst")
        log = load_approval_log(case_dir)
        assert len(log) == 2


class TestContentHash:
    def test_hash_excludes_volatile_fields(self):
        f1 = {"id": "F-001", "technique_id": "T1003.001", "status": "DRAFT",   "approved_by": ""}
        f2 = {"id": "F-001", "technique_id": "T1003.001", "status": "APPROVED","approved_by": "analyst"}
        # Same substantive content, different status — hash must match
        assert compute_content_hash(f1) == compute_content_hash(f2)

    def test_hash_changes_with_content(self):
        f1 = {"id": "F-001", "technique_id": "T1003.001"}
        f2 = {"id": "F-001", "technique_id": "T1569.002"}
        assert compute_content_hash(f1) != compute_content_hash(f2)


class TestVerifyIntegrity:
    def test_draft_findings_show_draft(self, case_dir):
        write_findings_from_audit(
            case_dir, "nfury",
            confirmed=["T1003.001"],
            inconclusive=[],
            refuted=[],
            transcript=[_SAMPLE_TRANSCRIPT[0]],
            examiner="analyst",
        )
        results = verify_approval_integrity(case_dir)
        assert all(r["verification"] == "draft" for r in results)

    def test_approved_finding_shows_confirmed(self, case_dir):
        write_findings_from_audit(
            case_dir, "nfury",
            confirmed=["T1003.001"],
            inconclusive=[],
            refuted=[],
            transcript=[_SAMPLE_TRANSCRIPT[0]],
            examiner="analyst",
        )
        # Simulate approval
        findings = load_findings(case_dir)
        findings[0]["status"]      = "APPROVED"
        findings[0]["approved_by"] = "analyst"
        findings[0]["content_hash"] = compute_content_hash(findings[0])
        save_findings(case_dir, findings)
        write_approval_log(case_dir, findings[0]["id"], "APPROVED", "analyst")

        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "confirmed"
