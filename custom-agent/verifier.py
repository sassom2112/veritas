#!/usr/bin/env python3
"""
verifier.py -- Phase 2: Same-Layer Blind Replication

Each LayerClaim is independently re-verified by a fresh agent session using
the same layer's tools. The verifier receives only the raw tool output and
artifact hint — never the investigator's reasoning chain.

The independence property is enforced structurally: _build_verifier_message()
is the sole point of handoff construction and never includes anything from
the investigator's conversation history. See ~/research/epistemic-through-line.md.

Budget: MAX_VERIFY_CALLS = 4 per claim (Phase 2 cap, separate from Phase 1).
All verifications run concurrently via asyncio.gather.
"""

import anthropic
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from contracts import LayerClaim, SameLayerVerdict

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

MAX_VERIFY_CALLS = 4   # Phase 2 budget per claim — DO NOT conflate with Phase 1 MAX_ROUNDS

# Forced tool schema for the verdict turn — model MUST call this, cannot return prose.
# Structurally different from _RECORD_FINDING_TOOL: verdict + citation, not a new finding.
_RECORD_VERDICT_TOOL = {
    'name': 'record_verdict',
    'description': 'Record your independent verification verdict for this technique claim.',
    'input_schema': {
        'type': 'object',
        'properties': {
            'verdict': {
                'type': 'string',
                'enum': ['CONFIRMED', 'REFUTED', 'INCONCLUSIVE'],
                'description': (
                    'CONFIRMED: your tools independently found artifact evidence. '
                    'REFUTED: your tools found contradicting evidence. '
                    'INCONCLUSIVE: insufficient visibility with available tools.'
                ),
            },
            'citation': {
                'type': 'string',
                'description': (
                    'What your tools found. Be specific: file path, registry key, '
                    'tool output line, or why the artifact was not locatable.'
                ),
            },
        },
        'required': ['verdict', 'citation'],
    },
}

_VERIFIER_SYSTEM = """\
You are a forensic verifier. Your only job is to independently confirm or refute
a specific technique claim using your available tools.

CRITICAL INFORMATION BOUNDARY:
You receive ONLY the raw tool output that served as evidence and an artifact hint.
You do NOT receive any reasoning, narrative, or analysis from the investigator.
This boundary is intentional and must not be circumvented.

Do not ask for additional context. Do not reference what the investigator concluded.
Run your own tools. Reach your own verdict.

Budget: 4 tool calls. Use them for targeted searches, not broad scans.
After your tool calls you will be asked to call record_verdict.
"""


def _build_verifier_message(
    claim: LayerClaim,
    target_path: str,
    memory_path: str | None,
) -> str:
    """
    Construct the handoff to the blind verifier.

    Enforcement point for the information boundary: only technique_id,
    technique_name, raw tool_output, and artifact_hint cross here.
    The investigator's reasoning chain is never passed into this function.
    """
    layer = claim['source_layer']
    target_line = (
        f"Disk image path: {target_path}" if layer == 'disk'
        else f"Memory image: {memory_path or 'path from MEMORY_PATH env'}"
    )
    return (
        f"TECHNIQUE TO VERIFY: {claim['technique_id']} — {claim['technique_name']}\n\n"
        f"{target_line}\n\n"
        f"RAW TOOL OUTPUT (the artifact — this is all you receive from the investigator):\n"
        f"{claim['tool_output'][:1500]}\n\n"
        f"ARTIFACT HINT: {claim['artifact_hint']}\n\n"
        f"Run your tools. Verify independently."
    )


async def _verify_one(
    claim: LayerClaim,
    target_path: str,
    memory_path: str | None,
    client: anthropic.Anthropic,
) -> SameLayerVerdict:
    """Verify a single claim with a fresh, isolated, same-layer MCP session."""
    layer = claim['source_layer']
    server_params = StdioServerParameters(
        command='python3',
        args=[os.path.join(_HERE, 'sift_server.py')],
        env={**os.environ, 'VERITAS_LAYER': layer},
    )

    print(f"  [verify/{layer}] {claim['technique_id']} ...", end='', flush=True)

    verdict  = 'INCONCLUSIVE'
    citation: str | None = None

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
                    'content': _build_verifier_message(claim, target_path, memory_path),
                }]

                call_count = 0
                while call_count < MAX_VERIFY_CALLS:
                    response = client.messages.create(
                        model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                        max_tokens=1024,
                        system=_VERIFIER_SYSTEM,
                        tools=tools,
                        messages=messages,
                    )
                    messages.append({'role': 'assistant', 'content': response.content})

                    tool_blocks = [b for b in response.content if b.type == 'tool_use']
                    if not tool_blocks:
                        break

                    tool_results = []
                    for block in tool_blocks:
                        if call_count >= MAX_VERIFY_CALLS:
                            tool_results.append({
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
                        call_count += 1
                        print('.', end='', flush=True)
                        tool_results.append({
                            'type': 'tool_result',
                            'tool_use_id': block.id,
                            'content': out[:2000],
                        })
                    messages.append({'role': 'user', 'content': tool_results})

                # Forced verdict — model cannot return prose
                messages.append({
                    'role': 'user',
                    'content': (
                        'Verification complete. Call record_verdict: '
                        'CONFIRMED if you found independent evidence, '
                        'REFUTED if you found contradicting evidence, '
                        'INCONCLUSIVE if your tools had insufficient visibility.'
                    ),
                })
                verdict_resp = client.messages.create(
                    model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                    max_tokens=512,
                    system=_VERIFIER_SYSTEM,
                    messages=messages,
                    tools=[_RECORD_VERDICT_TOOL],
                    tool_choice={'type': 'any'},
                )
                for block in verdict_resp.content:
                    if (hasattr(block, 'type') and block.type == 'tool_use'
                            and block.name == 'record_verdict'):
                        verdict  = block.input.get('verdict', 'INCONCLUSIVE')
                        citation = block.input.get('citation') or None
                        break

    except Exception as exc:
        verdict  = 'INCONCLUSIVE'
        citation = f'[Verifier session error: {exc}]'

    print(f' {verdict}')
    return SameLayerVerdict(
        technique_id=claim['technique_id'],
        source_layer=layer,
        verdict=verdict,
        citation=citation,
    )


async def verify_same_layer(
    claims: list[LayerClaim],
    target_path: str,
    memory_path: str | None,
) -> list[SameLayerVerdict]:
    """
    Phase 2 — PRIMARY GATE.

    All claims verified concurrently. Each gets a fresh, stateless MCP session
    on the same layer as the original claim. The information boundary (no
    investigator reasoning) is enforced in _build_verifier_message().

    Args:
        claims:      LayerClaim list from Phase 1 (disk_agent + memory_agent).
        target_path: Mounted disk path — passed to sift_server env.
        memory_path: Memory dump path — passed to sift_server env (may be None).

    Returns:
        SameLayerVerdict per claim, in the same order as claims.
        Caller filters on verdict == 'CONFIRMED' before Phase 3.
    """
    if not claims:
        return []

    client = anthropic.Anthropic()

    print(f"\n{'─'*60}")
    print(f"  PHASE 2: SAME-LAYER VERIFICATION  ({len(claims)} claims)")
    print(f"  Budget: {MAX_VERIFY_CALLS} calls/claim")
    print(f"{'─'*60}")

    verdicts = await asyncio.gather(
        *[_verify_one(c, target_path, memory_path, client) for c in claims]
    )

    confirmed    = sum(1 for v in verdicts if v['verdict'] == 'CONFIRMED')
    refuted      = sum(1 for v in verdicts if v['verdict'] == 'REFUTED')
    inconclusive = sum(1 for v in verdicts if v['verdict'] == 'INCONCLUSIVE')
    print(f"\n  Phase 2: {confirmed} confirmed / {refuted} refuted / {inconclusive} inconclusive")

    _write_audit(target_path, claims, list(verdicts))
    return list(verdicts)


def _write_audit(
    target_path: str,
    claims: list[LayerClaim],
    verdicts: list[SameLayerVerdict],
) -> None:
    host  = os.path.basename(target_path.rstrip('/'))
    entry = {
        'agent':     'verifier',
        'host':      host,
        'generated': datetime.now(timezone.utc).isoformat(),
        'verdicts':  list(verdicts),
    }
    path = os.path.join(_REPORTS, f'{host}-same-layer-verdicts.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(entry, f, indent=2)
