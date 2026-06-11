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
import re
import sys
from datetime import datetime, timezone
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from contracts import LayerClaim

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

MAX_ROUNDS         = 5   # investigation rounds
TOOLS_PER_ROUND    = 3   # tool calls per round

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

_SYNTHESIS_PROMPT = """\
Investigation complete. Output a JSON array of your CONFIRMED findings.

Each entry must follow this exact structure:
{
  "technique_id": "T1569.002",
  "technique_name": "System Services: Service Execution",
  "tool_name": "find",
  "tool_output": "EXACT output line that proves this — e.g. the file path returned by find",
  "artifact_hint": "psexesvc.exe at /mnt/nfury/Windows/psexesvc.exe"
}

Rules:
- Only include techniques where you found PHYSICAL DISK EVIDENCE in your tool calls above.
- tool_output must be the ACTUAL TEXT from a tool call, not a paraphrase.
- artifact_hint is a one-line pointer for the cross-verifier (what to look for and where).
- If no techniques confirmed, output: []

Respond with ONLY the JSON array. No prose, no markdown fences.
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

                # ── Structured synthesis ──────────────────────────────────
                messages.append({'role': 'user', 'content': _SYNTHESIS_PROMPT})
                synthesis = self.client.messages.create(
                    model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                    max_tokens=2048,
                    system=_DISK_AGENT_SYSTEM,
                    messages=messages,
                    tools=[],  # no tools in synthesis turn — text output only
                )

                raw_text = synthesis.content[0].text if synthesis.content else '[]'
                claims = self._parse_claims(raw_text, target_path, tool_count)

                # Write tool log to audit file
                self._write_audit(target_path, all_tool_outputs, claims)

                print(f"\n  Disk agent: {len(claims)} claim(s) from {tool_count} tool calls")
                for c in claims:
                    print(f"    {c['technique_id']}  {c['artifact_hint'][:60]}")

                return claims

    def _parse_claims(
        self,
        text: str,
        target_path: str,
        tool_count: int,
    ) -> list[LayerClaim]:
        # Strip markdown fences if present
        text = re.sub(r'```(?:json)?\s*', '', text).strip()
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            # Try to extract a JSON array from the text
            m = re.search(r'\[.*\]', text, re.DOTALL)
            if m:
                try:
                    raw = json.loads(m.group(0))
                except json.JSONDecodeError:
                    raw = []
            else:
                raw = []

        claims: list[LayerClaim] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            tid = entry.get('technique_id', '').strip()
            if not tid:
                continue
            claims.append(LayerClaim(
                technique_id=tid,
                technique_name=entry.get('technique_name', tid),
                source_layer='disk',
                tool_name=entry.get('tool_name', 'unknown'),
                tool_output=entry.get('tool_output', '')[:2000],
                artifact_hint=entry.get('artifact_hint', '')[:200],
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
