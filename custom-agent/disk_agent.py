#!/usr/bin/env python3
"""
disk_agent.py -- Disk Investigation Agent

Investigates a mounted Windows disk image using disk-only SIFT tools.
Connects to sift_server.py with VERITAS_LAYER=disk — vol.py and other
memory tools are structurally unavailable, not prompt-restricted.

Produces a list[LayerClaim]: each confirmed technique paired with the
raw tool output that supports it. Reasoning is written to audit_log.jsonl
and never included in LayerClaim — the cross-verifier receives evidence,
not narrative.

Usage (standalone):
    python3 custom-agent/disk_agent.py /mnt/nfury
"""

import anthropic
import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from contracts import LayerClaim

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

MAX_ROUNDS         = 5   # Phase 1 investigation rounds
TOOLS_PER_ROUND    = 3   # Phase 1 tool calls per round
# Phase 2 (same-layer verification) budget is set in verifier.py:
#   MAX_VERIFY_ROUNDS=2, TOOLS_PER_VERIFY=2  →  4 calls/claim
# Phase 3 (cross-layer corroboration) uses the same 4-call cap.
# Target: Phase 1 + Phase 2 + Phase 3 ≤ 100 tool calls/host, ≤ $20.

# Forced tool schema for claim synthesis — model MUST call this, cannot return prose.
# Defined here (not in sift_server.py) because it is a reporting primitive,
# not a forensic tool. The synthesis turn never connects to the MCP server.
_RECORD_FINDING_TOOL = {
    'name': 'record_finding',
    'description': (
        'Record one confirmed ATT&CK technique finding. '
        'Call once per confirmed technique. Do not call for INCONCLUSIVE findings.'
    ),
    'input_schema': {
        'type': 'object',
        'properties': {
            'technique_id': {
                'type': 'string',
                'description': 'MITRE ATT&CK ID, e.g. T1569.002',
            },
            'technique_name': {
                'type': 'string',
                'description': 'Human-readable technique name',
            },
            'tool_name': {
                'type': 'string',
                'description': 'The SIFT tool that produced the evidence, e.g. "find"',
            },
            'tool_output': {
                'type': 'string',
                'description': (
                    'The EXACT output text from your tool call that proves this technique. '
                    'Copy verbatim — do not paraphrase.'
                ),
            },
            'artifact_hint': {
                'type': 'string',
                'description': (
                    'One-line pointer for the verifier: what to look for and where. '
                    'E.g. "psexesvc.exe at /mnt/nfury/Windows/psexesvc.exe"'
                ),
            },
        },
        'required': [
            'technique_id', 'technique_name', 'tool_name',
            'tool_output', 'artifact_hint',
        ],
    },
}

_DISK_AGENT_SYSTEM = """\
You are the Disk Investigation Agent. You have access to disk-only forensic tools:
Sleuth Kit (fls, icat, fsstat), RegRipper (rip.pl), strings, grep, find, and
standard SIFT utilities. You do NOT have access to Volatility or memory analysis
tools — your job is the physical disk.

Your mission: investigate the mounted Windows disk image and identify which
ATT&CK techniques were used. For each technique you are confident about, you
need the PHYSICAL DISK EVIDENCE — a specific file path, registry key, or binary
content that proves it.

Investigation approach:
1. Start with fls to list suspicious directories (Recycle Bin, Temp, AppData)
2. Check prefetch for execution evidence (find /mnt -name '*.pf' -path '*/Prefetch/*')
3. Use rip.pl on registry hives for persistence, credentials, services
4. Use strings on suspicious binaries for C2 indicators and compiler artifacts
5. Check event logs via find for relevant .evtx files

Rules:
- String match alone is NOT proof. Find the file on disk.
- A find command that returns a path IS evidence.
- strings output containing a C2 domain IS evidence.
- A registry key value from rip.pl IS evidence.
- If you cannot find a physical artifact, do not claim the technique.

Call tools freely. After your investigation, you will be asked to output
structured JSON claims for each confirmed technique.
"""



class DiskAgent:
    """
    Investigates a mounted disk image using disk-only SIFT tools.
    Produces LayerClaim list — evidence crossing the layer boundary,
    reasoning quarantined in audit_log.jsonl.
    """

    def __init__(self):
        self.client = anthropic.Anthropic()

    async def investigate(
        self,
        target_path: str,
        ioc_data: dict | None = None,
    ) -> list[LayerClaim]:
        """
        Run disk investigation. Returns confirmed LayerClaims.
        Each claim contains raw tool output — no agent reasoning.
        """
        server_env = {**os.environ, 'VERITAS_LAYER': 'disk'}
        server_params = StdioServerParameters(
            command='python3',
            args=[os.path.join(_HERE, 'sift_server.py')],
            env=server_env,
        )

        print(f"\n{'─'*60}")
        print(f"  DISK AGENT  —  {target_path}")
        print(f"  Tools: disk-only (Sleuth Kit, RegRipper, SIFT)")
        print(f"  Budget: {MAX_ROUNDS} rounds × {TOOLS_PER_ROUND} tools")
        print(f"{'─'*60}")

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                mcp_tools = await session.list_tools()
                tools = [
                    {'name': t.name, 'description': t.description,
                     'input_schema': t.inputSchema}
                    for t in mcp_tools.tools
                ]

                ioc_context = ''
                if ioc_data:
                    ioc_context = (
                        f"\nCampaign IOCs from prior hosts:\n"
                        f"  C2 IPs: {ioc_data.get('c2_ips', [])}\n"
                        f"  Filenames: {ioc_data.get('filenames', [])}\n"
                        f"  Accounts: {ioc_data.get('accounts', [])}\n"
                    )

                messages = [{
                    'role': 'user',
                    'content': (
                        f"Mounted disk image: {target_path}\n"
                        f"Investigate this Windows disk image for attacker activity."
                        f"{ioc_context}\n"
                        f"Use up to {MAX_ROUNDS * TOOLS_PER_ROUND} tool calls total. "
                        f"Investigate systematically — filesystem, registry, "
                        f"prefetch, event logs, suspicious binaries."
                    ),
                }]

                tool_count = 0
                all_tool_outputs: list[dict] = []

                while tool_count < MAX_ROUNDS * TOOLS_PER_ROUND:
                    response = self.client.messages.create(
                        model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                        max_tokens=2048,
                        system=_DISK_AGENT_SYSTEM,
                        tools=tools,
                        messages=messages,
                    )

                    messages.append({'role': 'assistant', 'content': response.content})

                    tool_blocks = [b for b in response.content if b.type == 'tool_use']
                    if not tool_blocks:
                        break  # model finished investigating

                    tool_results = []
                    for block in tool_blocks:
                        if tool_count >= MAX_ROUNDS * TOOLS_PER_ROUND:
                            tool_results.append({
                                'type': 'tool_result',
                                'tool_use_id': block.id,
                                'content': '[BUDGET EXHAUSTED]',
                            })
                            continue
                        try:
                            result = await session.call_tool(block.name, block.input)
                            output = result.content[0].text
                        except Exception as exc:
                            output = f'[Tool error: {exc}]'

                        cmd = block.input.get('command', block.name)
                        all_tool_outputs.append({'cmd': cmd, 'output': output})
                        tool_count += 1
                        print(f"  [disk] [{tool_count:02d}] {cmd[:70]}")

                        tool_results.append({
                            'type': 'tool_result',
                            'tool_use_id': block.id,
                            'content': output[:3000],
                        })

                    messages.append({'role': 'user', 'content': tool_results})

                # ── Structured synthesis (forced tool_use — no text parsing) ──
                # tool_choice=any forces the model to call record_finding for each
                # confirmed technique. It cannot return prose. If nothing confirmed,
                # the model returns end_turn without calling the tool → empty list.
                messages.append({
                    'role': 'user',
                    'content': (
                        'Investigation complete. For each technique where you found '
                        'PHYSICAL DISK EVIDENCE in the tool calls above, call '
                        'record_finding once. Only call it for techniques with a '
                        'concrete artifact — a file path, registry value, or binary '
                        'content returned by an actual tool. Do not call it for '
                        'techniques you only inferred or suspected.'
                    ),
                })
                synthesis = self.client.messages.create(
                    model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                    max_tokens=2048,
                    system=_DISK_AGENT_SYSTEM,
                    messages=messages,
                    tools=[_RECORD_FINDING_TOOL],
                    tool_choice={'type': 'any'},
                )

                claims = self._collect_claims(synthesis.content)

                # Write tool log to audit file
                self._write_audit(target_path, all_tool_outputs, claims)

                print(f"\n  Disk agent: {len(claims)} claim(s) from {tool_count} tool calls")
                for c in claims:
                    print(f"    {c['technique_id']}  {c['artifact_hint'][:60]}")

                return claims

    @staticmethod
    def _collect_claims(content: list) -> list[LayerClaim]:
        """
        Extract LayerClaims from synthesis response content blocks.
        Each tool_use block with name='record_finding' is one claim.
        No text parsing — structure is enforced by tool_choice=any.
        """
        claims: list[LayerClaim] = []
        for block in content:
            if not hasattr(block, 'type') or block.type != 'tool_use':
                continue
            if block.name != 'record_finding':
                continue
            inp = block.input
            tid = inp.get('technique_id', '').strip()
            if not tid:
                continue
            claims.append(LayerClaim(
                technique_id=tid,
                technique_name=inp.get('technique_name', tid),
                source_layer='disk',
                tool_name=inp.get('tool_name', 'unknown'),
                tool_output=inp.get('tool_output', '')[:2000],
                artifact_hint=inp.get('artifact_hint', '')[:200],
            ))
        return claims

    def _write_audit(
        self,
        target_path: str,
        tool_outputs: list[dict],
        claims: list[LayerClaim],
    ) -> None:
        host = os.path.basename(target_path.rstrip('/'))
        entry = {
            'agent':      'disk_agent',
            'host':       host,
            'generated':  datetime.now(timezone.utc).isoformat(),
            'target':     target_path,
            'tool_calls': tool_outputs,
            'claims':     list(claims),
        }
        path = os.path.join(_REPORTS, f'{host}-disk-agent-log.json')
        os.makedirs(_REPORTS, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(entry, f, indent=2)


# ── Standalone entry point ─────────────────────────────────────────────────

async def _main():
    parser = argparse.ArgumentParser(
        description='Disk Investigation Agent — disk-only tool grants'
    )
    parser.add_argument('target', help='Mounted disk image path (e.g. /mnt/nfury)')
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"ERROR: {args.target} not found or not mounted")
        sys.exit(1)

    agent = DiskAgent()
    claims = await agent.investigate(args.target)
    print(f"\nClaims ({len(claims)}):")
    for c in claims:
        print(f"  {c['technique_id']}  [{c['source_layer']}]  {c['artifact_hint']}")


if __name__ == '__main__':
    asyncio.run(_main())
