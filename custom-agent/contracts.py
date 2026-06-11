"""
contracts.py -- Data contracts for the VERITAS pipeline.

Defines the TypedDicts that cross agent boundaries. These are the only
structures that should be passed between phases. If a key isn't here,
it doesn't belong in the handoff.
"""
from __future__ import annotations
from typing import TypedDict


class TriageHandoff(TypedDict):
    """
    What the triage phase passes to the Forensic Auditor.

    The Auditor receives technique IDs, their source layer, the raw signals
    that fired, and a log of Pass 2 tool calls it can use to seed verification.
    It does NOT receive scores, labels, or the triage agent's reasoning.
    """
    techniques_detected: list[str]         # MITRE IDs, e.g. ["T1134", "T1055"]
    technique_sources: dict[str, str]      # "disk" | "memory" | "disk+memory"
    matched_signals: dict[str, list[str]]  # raw signal strings per technique
    confidence_score: int                  # combined triage score (not shown to Auditor)
    pass2_tool_log: list[dict]             # agentic tool calls, used to seed verification
    target: str                            # mounted disk path


class AuditResult(TypedDict):
    """
    What ForensicAuditor.audit() returns.

    Replaces the bare 5-tuple. Positional unpacking was silently wrong
    if the return order changed.
    """
    confirmed: list[str]      # technique IDs with positive tool-return evidence
    inconclusive: list[str]   # technique IDs where evidence could not be located
    refuted: list[str]        # technique IDs where evidence was absent or contradicted
    transcript: list[dict]    # full per-technique challenge log
    adjusted_score: int       # sum of confirmed technique weights, capped at 100


# ── Cross-layer verification contracts ────────────────────────────────────────
# Used by disk_agent.py, memory_agent.investigate_layered(), and cross_verifier.py.
# The key invariant: reasoning never crosses the layer boundary.
# Only tool_output and technique_id travel between agents.

class LayerClaim(TypedDict):
    """
    A single technique claim produced by disk_agent or memory_agent.

    Crosses the layer boundary stripped of reasoning. The verifying agent
    receives tool_output (what the filesystem/memory actually said) and
    artifact_hint (where to look), but never the original agent's analysis.

    A hallucinated claim has no tool_output that corresponds to real evidence —
    the verifying layer finds nothing and returns NO_VISIBILITY or CONTRADICTED.
    """
    technique_id: str         # MITRE ID: "T1134"
    technique_name: str       # Human-readable: "Access Token Manipulation"
    source_layer: str         # "disk" | "memory"
    tool_name: str            # The tool that produced this evidence
    tool_output: str          # Raw tool output — reasoning quarantined in audit log
    artifact_hint: str        # Brief pointer: "psexesvc.exe at C:\\Windows\\psexesvc.exe"


class CrossVerdict(TypedDict):
    """
    Result of a cross-layer verification attempt.

    NO_VISIBILITY is not REFUTED. Fileless malware confirmed in memory
    has no disk shadow — the disk verifier correctly returns NO_VISIBILITY.
    Single-sourced findings are reported as SINGLE_SOURCE, not dismissed.
    """
    technique_id: str
    source_layer: str         # where the claim originated: "disk" | "memory"
    verifying_layer: str      # which layer attempted verification: "memory" | "disk"
    verdict: str              # "CORROBORATED" | "CONTRADICTED" | "NO_VISIBILITY"
    citation: str | None      # what the verifying layer found, or None


class FinalTechniqueResult(TypedDict):
    """
    Adjudicated result after both layers have been heard.

    CONFIRMED    — source confirmed + cross-layer CORROBORATED (highest confidence)
    SINGLE_SOURCE — source confirmed + cross-layer NO_VISIBILITY (single-sourced)
    DISPUTED     — source confirmed but cross-layer CONTRADICTED (needs human review)
    REFUTED      — source found no evidence
    """
    technique_id: str
    technique_name: str
    source_layer: str
    cross_verdict: str        # raw CrossVerdict.verdict
    final: str                # "CONFIRMED" | "SINGLE_SOURCE" | "DISPUTED" | "REFUTED"
    citation: str | None
