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
