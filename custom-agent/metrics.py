#!/usr/bin/env python3
"""
metrics.py -- Session-level token and cost telemetry.

A single Metrics instance is created by investigate.py at the start of each
host investigation and passed into Phase 2 (verify_same_layer) and Phase 3
(CrossVerifier.verify_all). Each agent calls record_call() after every
client.messages.create() response. The orchestrator reads total_cost_usd()
at the Phase 2/3 gate and writes the manifest at the end.

Pricing vectors are approximate 2026 rates. Update _PRICE_PER_TOKEN if
Anthropic changes pricing — this is the single source of truth for cost math.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

_PRICE_PER_TOKEN: Dict[str, tuple] = {
    'claude-sonnet-4-6':         (3.00 / 1_000_000, 15.00 / 1_000_000),
    'claude-haiku-4-5-20251001': (0.80 / 1_000_000,  4.00 / 1_000_000),
}
_FALLBACK_MODEL = 'claude-sonnet-4-6'


class Metrics:
    """Accumulates token usage and computes running cost across all API calls."""

    def __init__(self) -> None:
        self._start       = time.monotonic()
        self._calls: List[Dict[str, Any]] = []
        self._phases: Dict[str, Dict[str, Any]] = {}
        self._phase_starts: Dict[str, float] = {}
        self._phase_ends:   Dict[str, float] = {}

    # ── Phase timing ──────────────────────────────────────────────────────────

    def start_phase(self, phase: str) -> None:
        self._phase_starts[phase] = time.monotonic()
        if phase not in self._phases:
            self._phases[phase] = {
                'input_tokens':  0,
                'output_tokens': 0,
                'cost_usd':      0.0,
                'duration_ms':   0,
            }

    def end_phase(self, phase: str) -> None:
        if phase in self._phase_starts:
            elapsed = time.monotonic() - self._phase_starts[phase]
            self._phase_ends[phase] = time.monotonic()
            if phase in self._phases:
                self._phases[phase]['duration_ms'] = int(elapsed * 1000)

    # ── Per-call recording ────────────────────────────────────────────────────

    def record_call(self, model: str, usage: Any, phase: str) -> None:
        """Record token usage for one API call. Call immediately after messages.create()."""
        rates = _PRICE_PER_TOKEN.get(model, _PRICE_PER_TOKEN[_FALLBACK_MODEL])
        in_cost  = usage.input_tokens  * rates[0]
        out_cost = usage.output_tokens * rates[1]
        call_cost = in_cost + out_cost

        self._calls.append({
            'model':         model,
            'phase':         phase,
            'input_tokens':  usage.input_tokens,
            'output_tokens': usage.output_tokens,
            'cost_usd':      call_cost,
        })

        if phase not in self._phases:
            self._phases[phase] = {
                'input_tokens':  0,
                'output_tokens': 0,
                'cost_usd':      0.0,
                'duration_ms':   0,
            }
        self._phases[phase]['input_tokens']  += usage.input_tokens
        self._phases[phase]['output_tokens'] += usage.output_tokens
        self._phases[phase]['cost_usd']      += call_cost

    # ── Aggregates ────────────────────────────────────────────────────────────

    def total_cost_usd(self) -> float:
        return sum(c['cost_usd'] for c in self._calls)

    def total_input_tokens(self) -> int:
        return sum(c['input_tokens'] for c in self._calls)

    def total_output_tokens(self) -> int:
        return sum(c['output_tokens'] for c in self._calls)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(
        self,
        case_id: str,
        host: str,
        verdicts_summary: Dict[str, int],
    ) -> Dict[str, Any]:
        elapsed_ms = int((time.monotonic() - self._start) * 1000)
        return {
            'case_id':              case_id,
            'target_host':          host,
            'total_cost_usd':       round(self.total_cost_usd(), 4),
            'total_input_tokens':   self.total_input_tokens(),
            'total_output_tokens':  self.total_output_tokens(),
            'execution_duration_ms': elapsed_ms,
            'phases':               self._phases,
            'verdicts_summary':     verdicts_summary,
        }
