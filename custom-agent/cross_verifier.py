#!/usr/bin/env python3
"""
cross_verifier.py -- Cross-Layer Verification Engine

Each layer's claims are verified by the OTHER layer.
Disk agent claims  → memory verifier (vol.py only)
Memory agent claims → disk verifier  (Sleuth Kit / SIFT only)

The key property: the verifier receives the raw TOOL OUTPUT from the other
layer (not the agent's reasoning), plus the technique ID. It must find
corroborating or contradicting evidence independently.

Three verdicts:
  CORROBORATED  — verifying layer found supporting evidence
  CONTRADICTED  — verifying layer found evidence against the claim
  NO_VISIBILITY — verifying layer has no view into this artifact type

NO_VISIBILITY is not REFUTED. Fileless malware injected into memory
has no disk shadow. A disk verifier correctly returns NO_VISIBILITY for
a memory-resident shellcode claim — the claim remains SINGLE_SOURCE,
not dismissed. This preserves the architecture's most important findings.

Final adjudication (see investigate.py):
  CORROBORATED  → CONFIRMED      (causal coupling across layers demonstrated)
  NO_VISIBILITY → SINGLE_SOURCE  (single-sourced, reported with caveat)
  CONTRADICTED  → DISPUTED       (flag for human review)
"""

import anthropic
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from contracts import CrossVerdict, FinalTechniqueResult, LayerClaim, SameLayerVerdict

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

MAX_VERIFY_ROUNDS   = 3   # rounds per claim
TOOLS_PER_VERIFY    = 2   # tool calls per round

_DISK_VERIFIER_SYSTEM = """\
You are the Disk Verifier. You have access to disk-only SIFT tools: Sleuth Kit
(fls, icat, fsstat), RegRipper (rip.pl), strings, grep, find, and standard SIFT
utilities. You do NOT have access to Volatility.

A MEMORY agent has made a claim about attacker activity. You are given:
- The technique it claims: ATT&CK technique ID and name
- The EXACT tool output it produced as evidence (from memory analysis)
- A hint about what artifact to look for

Your job: using disk tools ONLY, determine whether there is a disk-layer
corroboration or contradiction.

Verdicts:
  CORROBORATED — you found a disk artifact that supports this technique
    (e.g. the binary exists on disk, the registry key is present,
     prefetch confirms execution of the named process)
  CONTRADICTED — you found positive disk evidence AGAINST this technique
    (e.g. memory said a binary was injected but disk shows the path
     is a known-clean Windows system binary with no suspicious strings)
  NO_VISIBILITY — this technique is memory-resident by nature and disk
    has no view into it. Use this for:
    - Shellcode in anonymous memory regions (no file backing by definition)
    - Network connections visible only in kernel memory
    - Credentials in LSASS process space (not yet written to disk)
    Fileless techniques SHOULD return NO_VISIBILITY — that is correct behavior.

End your response with exactly one of:
CROSS_VERDICT: CORROBORATED
CROSS_VERDICT: CONTRADICTED
CROSS_VERDICT: NO_VISIBILITY
"""

_MEMORY_VERIFIER_SYSTEM = """\
You are the Memory Verifier. You have access to Volatility 3 ONLY (vol.py).
You do NOT have access to Sleuth Kit, RegRipper, or any disk tools.

A DISK agent has made a claim about attacker activity. You are given:
- The technique it claims: ATT&CK technique ID and name
- The EXACT tool output it produced as evidence (from disk analysis)
- A hint about what artifact to look for

Your job: using Volatility 3 ONLY, determine whether there is a memory-layer
corroboration or contradiction.

Verdicts:
  CORROBORATED — you found memory evidence supporting this technique
    (e.g. process is running and consistent with the disk artifact,
     VAD regions show active execution of the binary found on disk,
     network connections match the C2 found in binary strings)
  CONTRADICTED — you found memory evidence AGAINST this technique
    (e.g. disk said a service was installed but no such process runs,
     disk found a persistence key but the process never executed)
  NO_VISIBILITY — this technique leaves no consistent memory trace.
    Use this for:
    - Archive utilities that ran and exited (no resident process)
    - Registry modifications (done, process gone)
    - File timestamps (purely disk-layer, no memory analog)

End your response with exactly one of:
CROSS_VERDICT: CORROBORATED
CROSS_VERDICT: CONTRADICTED
CROSS_VERDICT: NO_VISIBILITY
"""


class CrossVerifier:
    """
    Verifies LayerClaims from one layer using the opposite layer's tools.
    All verification sessions run concurrently via asyncio.gather.
    """

    def __init__(self):
        self.client = anthropic.Anthropic()

    async def verify_all(
        self,
        disk_claims: list[LayerClaim],
        memory_claims: list[LayerClaim],
        target_path: str,
        memory_path: str | None,
    ) -> tuple[list[CrossVerdict], list[CrossVerdict]]:
        """
        Cross-verify both claim sets concurrently.
        Returns (disk_verdicts, memory_verdicts).
        Disk claims are verified by memory. Memory claims are verified by disk.
        """
        print(f"\n{'─'*60}")
        print(f"  CROSS-LAYER VERIFICATION")
        print(f"  Disk claims → memory verifier: {len(disk_claims)}")
        print(f"  Memory claims → disk verifier: {len(memory_claims)}")
        print(f"{'─'*60}")

        disk_tasks = [
            self._verify_one(claim, target_path, memory_path, verifying_layer='memory')
            for claim in disk_claims
            if memory_path  # can only verify disk claims via memory if we have a dump
        ]
        memory_tasks = [
            self._verify_one(claim, target_path, memory_path, verifying_layer='disk')
            for claim in memory_claims
        ]

        # Unverifiable disk claims (no memory image) get NO_VISIBILITY automatically
        unverifiable_disk = [
            CrossVerdict(
                technique_id=c['technique_id'],
                source_layer='disk',
                verifying_layer='memory',
                verdict='NO_VISIBILITY',
                citation='No memory image available for cross-verification',
            )
            for c in disk_claims if not memory_path
        ]

        results = await asyncio.gather(*(disk_tasks + memory_tasks))

        n_disk   = len(disk_tasks)
        disk_verdicts   = list(results[:n_disk]) + unverifiable_disk
        memory_verdicts = list(results[n_disk:])

        self._write_audit(target_path, disk_verdicts, memory_verdicts)
        return disk_verdicts, memory_verdicts

    async def _verify_one(
        self,
        claim: LayerClaim,
        target_path: str,
        memory_path: str | None,
        verifying_layer: str,
    ) -> CrossVerdict:
        """Verify a single claim with one bounded MCP session."""
        if verifying_layer == 'memory':
            layer_env   = 'memory'
            system      = _MEMORY_VERIFIER_SYSTEM
            target      = memory_path
        else:
            layer_env   = 'disk'
            system      = _DISK_VERIFIER_SYSTEM
            target      = target_path

        server_params = StdioServerParameters(
            command='python3',
            args=[os.path.join(_HERE, 'sift_server.py')],
            env={**os.environ, 'VERITAS_LAYER': layer_env},
        )

        print(f"  [{claim['technique_id']}] {claim['source_layer']}→{verifying_layer} ...",
              end='', flush=True)

        verdict  = 'NO_VISIBILITY'
        citation = None
        tool_outputs: list[str] = []

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    mcp_tools = await session.list_tools()
                    tools = [
                        {'name': t.name, 'description': t.description,
                         'input_schema': t.inputSchema}
                        for t in mcp_tools.tools
                    ]

                    messages = [{
                        'role': 'user',
                        'content': (
                            f"Target: {target}\n"
                            f"Claim to verify:\n"
                            f"  Technique:     {claim['technique_id']} — {claim['technique_name']}\n"
                            f"  Source layer:  {claim['source_layer']}\n"
                            f"  Tool evidence: {claim['tool_output'][:1000]}\n"
                            f"  Artifact hint: {claim['artifact_hint']}\n\n"
                            f"Using {verifying_layer}-layer tools ONLY, "
                            f"determine if this claim is CORROBORATED, CONTRADICTED, "
                            f"or NO_VISIBILITY from your layer. "
                            f"Use up to {MAX_VERIFY_ROUNDS * TOOLS_PER_VERIFY} tool calls. "
                            f"End with: CROSS_VERDICT: <CORROBORATED|CONTRADICTED|NO_VISIBILITY>"
                        ),
                    }]

                    tool_count = 0
                    while tool_count < MAX_VERIFY_ROUNDS * TOOLS_PER_VERIFY:
                        response = self.client.messages.create(
                            model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                            max_tokens=1024,
                            system=system,
                            tools=tools,
                            messages=messages,
                        )
                        messages.append({'role': 'assistant', 'content': response.content})

                        tool_blocks = [b for b in response.content if b.type == 'tool_use']
                        if not tool_blocks:
                            text = response.content[0].text if response.content else ''
                            verdict  = self._parse_verdict(text)
                            citation = self._extract_citation(text)
                            break

                        results_block = []
                        for block in tool_blocks:
                            if tool_count >= MAX_VERIFY_ROUNDS * TOOLS_PER_VERIFY:
                                results_block.append({
                                    'type': 'tool_result',
                                    'tool_use_id': block.id,
                                    'content': '[BUDGET EXHAUSTED]',
                                })
                                continue
                            try:
                                r = await session.call_tool(block.name, block.input)
                                out = r.content[0].text
                            except Exception as exc:
                                out = f'[Tool error: {exc}]'
                            tool_outputs.append(out[:1000])
                            tool_count += 1
                            results_block.append({
                                'type': 'tool_result',
                                'tool_use_id': block.id,
                                'content': out[:2000],
                            })
                        messages.append({'role': 'user', 'content': results_block})

        except Exception as exc:
            verdict = 'NO_VISIBILITY'
            citation = f'[Verifier error: {exc}]'

        print(f" {verdict}")
        return CrossVerdict(
            technique_id=claim['technique_id'],
            source_layer=claim['source_layer'],
            verifying_layer=verifying_layer,
            verdict=verdict,
            citation=citation,
        )

    @staticmethod
    def _parse_verdict(text: str) -> str:
        upper = text.upper()
        for line in upper.splitlines():
            line = line.strip()
            if line.startswith('CROSS_VERDICT:'):
                if 'CORROBORATED' in line:  return 'CORROBORATED'
                if 'CONTRADICTED' in line:  return 'CONTRADICTED'
                if 'NO_VISIBILITY' in line: return 'NO_VISIBILITY'
        # Fallback
        if 'CORROBORATED' in upper:  return 'CORROBORATED'
        if 'CONTRADICTED' in upper:  return 'CONTRADICTED'
        return 'NO_VISIBILITY'

    @staticmethod
    def _extract_citation(text: str) -> str | None:
        lines = [l.strip() for l in text.splitlines()
                 if l.strip() and 'CROSS_VERDICT' not in l.upper()]
        return ' '.join(lines)[:400] if lines else None

    def _write_audit(
        self,
        target_path: str,
        disk_verdicts: list[CrossVerdict],
        memory_verdicts: list[CrossVerdict],
    ) -> None:
        host = os.path.basename(target_path.rstrip('/'))
        entry = {
            'agent':           'cross_verifier',
            'host':            host,
            'generated':       datetime.now(timezone.utc).isoformat(),
            'disk_verdicts':   list(disk_verdicts),
            'memory_verdicts': list(memory_verdicts),
        }
        path = os.path.join(_REPORTS, f'{host}-cross-verdicts.json')
        os.makedirs(_REPORTS, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(entry, f, indent=2)


def adjudicate(
    same_layer_verdicts: list[SameLayerVerdict],
    disk_claims: list[LayerClaim],
    memory_claims: list[LayerClaim],
    disk_verdicts: list[CrossVerdict],
    memory_verdicts: list[CrossVerdict],
) -> list[FinalTechniqueResult]:
    """
    Map same-layer verdicts + cross-verdicts to a final result per technique.

    same_layer_verdict drives final; cross_verdict is annotation only.
    A Phase 3 CONTRADICTED cannot rescue a Phase 2 REFUTED.
    A Phase 3 CORROBORATED upgrades Phase 2 CONFIRMED → HIGH_CONFIRMED.
    """
    same_map: dict[str, SameLayerVerdict] = {v['technique_id']: v for v in same_layer_verdicts}

    cross_map: dict[str, CrossVerdict] = {}
    for v in disk_verdicts + memory_verdicts:
        tid = v['technique_id']
        existing = cross_map.get(tid)
        if existing is None or _cross_rank(v['verdict']) > _cross_rank(existing['verdict']):
            cross_map[tid] = v

    claim_map: dict[str, LayerClaim] = {}
    for c in disk_claims + memory_claims:
        tid = c['technique_id']
        if tid not in claim_map:
            claim_map[tid] = c

    results: list[FinalTechniqueResult] = []
    for tid, claim in claim_map.items():
        sv = same_map.get(tid)
        cv = cross_map.get(tid)
        same_v  = sv['verdict'] if sv else 'INCONCLUSIVE'
        cross_v = cv['verdict'] if cv else 'NO_VISIBILITY'
        results.append(FinalTechniqueResult(
            technique_id=tid,
            technique_name=claim['technique_name'],
            source_layer=claim['source_layer'],
            same_verdict=same_v,
            cross_verdict=cross_v,
            final=_final(same_v, cross_v),
            citation=cv['citation'] if cv else (sv['citation'] if sv else None),
        ))

    _rank = {'HIGH_CONFIRMED': 4, 'CONFIRMED': 3, 'DISPUTED': 2, 'REFUTED': 1, 'INCONCLUSIVE': 0}
    results.sort(key=lambda r: _rank.get(r['final'], 0), reverse=True)
    return results


def _cross_rank(v: str) -> int:
    return {'CORROBORATED': 2, 'NO_VISIBILITY': 1, 'CONTRADICTED': 0}.get(v, 0)


def _final(same_verdict: str, cross_verdict: str) -> str:
    """Same-layer drives final; cross-layer annotates CONFIRMED only."""
    if same_verdict == 'REFUTED':
        return 'REFUTED'
    if same_verdict == 'INCONCLUSIVE':
        return 'INCONCLUSIVE'
    # same_verdict == 'CONFIRMED'
    return {
        'CORROBORATED':  'HIGH_CONFIRMED',
        'NO_VISIBILITY': 'CONFIRMED',
        'CONTRADICTED':  'DISPUTED',
    }.get(cross_verdict, 'CONFIRMED')
