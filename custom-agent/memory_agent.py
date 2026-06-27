#!/usr/bin/env python3
"""
memory_agent.py -- Memory Agent

Volatility 3 based memory analysis — mirrors blue_agent.py two-pass structure.
  Pass 1: ~14 deterministic vol.py plugin runs scored against MEMORY_PATTERNS
  Pass 2: Agentic vol.py investigation loop (if score >= 5)

Output: reports/{host}-memory-triage-report.json

vol.py must be in PATH on the SIFT workstation, or set VOL_PATH env var:
    export VOL_PATH=/opt/volatility3/bin/vol
"""

import asyncio
import json
import logging
import os
import shlex
import sys
from datetime import datetime, timezone

import anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

# vol.py invocation — override with VOL_PATH if not in PATH
_VOL = os.environ.get('VOL_PATH', '/opt/volatility3/bin/vol')

MAX_AGENT_TOOLS = 60   # memory pass 2: vol.py queries + final synthesis

# ── Memory-domain ATT&CK patterns ────────────────────────────────────────────
# Signals are strings that appear in actual Volatility 3 plugin output,
# not Sysmon event log format. Different domain from operational_rules.json.

MEMORY_PATTERNS = {
    'T1055': {
        'name': 'Process Injection',
        'signals': [
            'page_execute_readwrite',  # malfind — RWX region = injected shellcode
            'vads',                    # malfind — anonymous private VAD (no file backing)
            'injected',                # malfind summary line
        ],
        'weight': 65,
    },
    'T1059.001': {
        'name': 'PowerShell / Encoded Execution',
        'signals': [
            '-enc',
            '-encodedcommand',
            'invoke-expression',
            'iex(',
            '-executionpolicy bypass',
        ],
        'weight': 50,
    },
    'T1003.001': {
        'name': 'Credential Dumping: LSASS',
        'signals': [
            'mimikatz',
            'sekurlsa',
            'procdump',
            'comsvcs',
            'minidump',
        ],
        'weight': 50,
    },
    'T1003.002': {
        'name': 'Credential Dumping: SAM / hashdump',
        'signals': [
            'aad3b435b51404eeaad3b435b51404ee',   # blank LM hash in hashdump output
            ':500:',                                # RID 500 = Administrator in hashdump
        ],
        'weight': 50,
    },
    'T1569.002': {
        'name': 'PsExec / Service Execution',
        'signals': [
            'psexesvc',
            'psexec',
        ],
        'weight': 50,
    },
    'T1071.001': {
        'name': 'C2 Web Protocol',
        'signals': [
            'established',   # netscan state — active outbound connection
            'close_wait',    # netscan — connection waiting on remote close
            'syn_sent',      # netscan — outbound TCP handshake in progress
        ],
        'weight': 35,
    },
    'T1547.001': {
        'name': 'Registry Run Key Persistence',
        'signals': [
            'currentversion\\run',
            'runonce',
        ],
        'weight': 35,
    },
    'T1574': {
        'name': 'DLL Side-Loading / Hijacking',
        'signals': [
            # ldrmodules False columns: DLL present in load order but absent from
            # init list or memory mapping — classic DLL injection artifact
            'false\t',
        ],
        'weight': 50,
    },
    'T1134': {
        'name': 'Access Token Manipulation',
        'signals': [
            'sedebugprivilege',
            'seimpersonateprivilege',
        ],
        'weight': 40,
    },
}


# ── Scoring engine ────────────────────────────────────────────────────────────

def parse_memory_findings(tool_outputs: list[str]) -> tuple:
    """
    Score Volatility plugin output against MEMORY_PATTERNS.
    Same half-weight-for-single-signal logic as blue_agent.parse_findings.
    """
    text = ' '.join(tool_outputs).lower().replace('\\\\', '\\')
    score, hits, reasons = 0, {}, []

    for tid, data in MEMORY_PATTERNS.items():
        matched = [s for s in data['signals']
                   if s.lower().replace('\\\\', '\\') in text]
        if not matched:
            continue

        weight = data['weight'] if len(matched) >= 2 else data['weight'] // 2
        if weight > 0:
            score += weight
            hits[tid] = matched
            reasons.append(f"{data['name']} (+{weight}) [memory] via: {matched}")

    return min(score, 100), hits, reasons


# ── Pass 1 command builder ────────────────────────────────────────────────────

def _build_memory_commands(memory_path: str) -> list[tuple[str, str]]:
    f = shlex.quote(memory_path)
    v = shlex.quote(_VOL)
    return [
        ('mem_pslist',
         f"{v} -q -f {f} windows.pslist 2>/dev/null | head -60"),
        ('mem_pstree',
         f"{v} -q -f {f} windows.pstree 2>/dev/null | head -60"),
        ('mem_cmdline',
         f"{v} -q -f {f} windows.cmdline 2>/dev/null | head -80"),
        ('mem_netscan',
         f"{v} -q -f {f} windows.netscan 2>/dev/null | head -60"),
        ('mem_malfind',
         f"{v} -q -f {f} windows.malfind 2>/dev/null | head -100"),
        ('mem_svcscan',
         f"{v} -q -f {f} windows.svcscan 2>/dev/null | head -60"),
        ('mem_hashdump',
         f"{v} -q -f {f} windows.hashdump 2>/dev/null | head -30"),
        ('mem_ldrmodules',
         f"{v} -q -f {f} windows.ldrmodules 2>/dev/null "
         f"| grep -E '\\bFalse\\b' | head -50"),
        ('mem_dlllist_suspicious',
         f"{v} -q -f {f} windows.dlllist 2>/dev/null "
         f"| grep -iE 'temp|appdata|users|programdata' | head -40"),
        ('mem_filescan',
         f"{v} -q -f {f} windows.filescan 2>/dev/null "
         f"| grep -iE '\\.exe|\\.dll|\\.ps1' | head -60"),
        ('mem_reg_run',
         f"{v} -q -f {f} windows.registry.printkey "
         f"--key 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' "
         f"2>/dev/null | head -30"),
        ('mem_privileges',
         f"{v} -q -f {f} windows.privileges 2>/dev/null "
         f"| grep -iE 'SeDebug|SeImpersonat' | head -30"),
        ('mem_handles_lsass',
         f"{v} -q -f {f} windows.handles 2>/dev/null "
         f"| grep -i 'lsass' | head -20"),
        ('mem_envars',
         f"{v} -q -f {f} windows.envars 2>/dev/null "
         f"| grep -iE 'temp|staging|payload|appdata' | head -30"),
    ]


# ── Pass 2 agent system prompt ────────────────────────────────────────────────

_AGENT_SYSTEM = """\
You are an experienced DFIR analyst conducting live memory forensics on a SANS \
SIFT workstation using Volatility 3. A fast deterministic sweep has already run. \
Your job is to go deep on suspicious memory findings.

MEMORY INVESTIGATION DISCIPLINE — for every suspicious process or injection hit:
  1. vol.py -q -f <mem> windows.cmdline --pid <pid>    (full command line)
  2. vol.py -q -f <mem> windows.handles --pid <pid>    (open handles — lsass access?)
  3. vol.py -q -f <mem> windows.dlllist --pid <pid>    (loaded modules)
  4. vol.py -q -f <mem> windows.vadwalk --pid <pid>    (VAD regions — injected pages?)

For every active network connection (ESTABLISHED):
  vol.py -q -f <mem> windows.netscan 2>/dev/null | grep <pid>   (full socket details)

For credential theft indicators:
  vol.py -q -f <mem> windows.hashdump   (SAM credential hashes)
  vol.py -q -f <mem> windows.lsadump    (LSA secrets)

For every PAGE_EXECUTE_READWRITE region (injection candidate):
  vol.py -q -f <mem> windows.dumpfiles --physaddr <addr> 2>/dev/null
  then: strings on the dumped file | head -40

Use VOL_PATH env var or replace vol.py with the full path if needed.
Call run_terminal_command with real vol.py commands. Do NOT repeat Pass 1 commands.

FINAL ASSESSMENT — structured markdown with two required sections:

## Memory Attack Chain
| PID | Process | Technique | Evidence |
|-----|---------|-----------|---------|
One row per confirmed in-memory finding.

## Memory IOCs
- Injected PIDs, suspicious processes, active C2 connections, credential artifacts.
Be specific. Cite plugin output. State confidence (HIGH/MED/LOW) per finding.
"""


# ── Report writer ─────────────────────────────────────────────────────────────

def save_memory_report(host: str, memory_path: str, score: int, hits: dict,
                       reasons: list, tool_outputs: list, analysis_text: str,
                       pass_info: dict = None) -> str:
    report = {
        'generated':          datetime.now(timezone.utc).isoformat(),
        'memory_path':        memory_path,
        'host':               host,
        'agent':              'memory-triage-agent',
        'two_pass_scan':      pass_info,
        'confidence_score':   score,
        'confidence_level':   _level(score),
        'techniques_detected': list(hits.keys()),
        'matched_signals':    hits,
        'detection_reasons':  reasons,
        'tool_outputs_count': len(tool_outputs),
        'memory_analysis':    analysis_text,
    }
    path = os.path.join(_REPORTS, f'{host}-memory-triage-report.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n  Memory report saved -> {path}")
    return path


def _level(score: int) -> str:
    if score >= 70: return 'HIGH'
    if score >= 40: return 'MEDIUM'
    return 'LOW'


# ── Main investigation coroutine ──────────────────────────────────────────────

async def investigate(memory_path: str, host: str,
                      no_synthesis: bool = False) -> tuple[int, dict]:
    """
    Full memory triage: Pass 1 vol.py sweep -> optional Pass 2 agentic loop.
    Returns (score, hits) — same contract as blue_agent.investigate().
    """
    client = anthropic.Anthropic()
    tool_outputs: list[str] = []

    server_params = StdioServerParameters(
        command='python3',
        args=[os.path.join(_HERE, 'sift_server.py')],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── Pass 1: Deterministic vol.py sweep ───────────────────────────
            print(f"\n── Memory Pass 1: Volatility scan "
                  f"({len(_build_memory_commands(memory_path))} plugins) ────")
            t0 = datetime.now(timezone.utc)

            for label, cmd in _build_memory_commands(memory_path):
                try:
                    result = await session.call_tool(
                        'run_terminal_command', {'command': cmd}
                    )
                    output = result.content[0].text
                    if output.strip() and not output.startswith('ERROR:'):
                        tool_outputs.append(output)
                        print(f"  [M1] {label}: {len(output)} bytes")
                    else:
                        print(f"  [M1] {label}: (empty)")
                except Exception as exc:
                    print(f"  [M1] {label} error: {exc}")

            pass1_score, pass1_hits, pass1_reasons = parse_memory_findings(tool_outputs)
            elapsed1 = (datetime.now(timezone.utc) - t0).total_seconds()
            print(f"\n  Memory score: {pass1_score}  ({elapsed1:.1f}s)")
            for r in pass1_reasons:
                print(f"    • {r}")

            pass_info = {
                'pass1_score': pass1_score,
                'pass1_hits':  list(pass1_hits.keys()),
                'pass2_ran':   False,
            }
            final_score   = pass1_score
            final_hits    = pass1_hits
            final_reasons = pass1_reasons
            analysis_text = ''

            # ── Pass 2: Agentic vol.py loop ───────────────────────────────────
            if no_synthesis or pass1_score < 5:
                skip = '--no-synthesis' if no_synthesis else f'low confidence (score={pass1_score})'
                print(f"\n── Memory Pass 2 skipped ({skip}) ────────────────────")
            else:
                print(f"\n── Memory Pass 2: Agentic investigation "
                      f"(budget: {MAX_AGENT_TOOLS} calls) ─────")
                t2 = datetime.now(timezone.utc)

                mcp_tools = await session.list_tools()
                tools = [
                    {'name': t.name, 'description': t.description,
                     'input_schema': t.inputSchema}
                    for t in mcp_tools.tools
                ]

                collected = "\n\n---\n".join(
                    f"[M1:{i+1}]:\n{out[:500]}"
                    for i, out in enumerate(tool_outputs)
                )

                messages = [{
                    'role': 'user',
                    'content': (
                        f"Memory image: {memory_path}\n"
                        f"Host: {host}\n"
                        f"Pass 1 score: {pass1_score}  Hits: {list(pass1_hits.keys())}\n\n"
                        f"Pass 1 output (excerpted):\n{collected[:6000]}\n\n"
                        f"Investigate the memory artifacts above. Use vol.py commands "
                        f"to go deeper on suspicious processes, injected regions, "
                        f"network connections, and credential artifacts. "
                        f"Budget: {MAX_AGENT_TOOLS} tool calls total."
                    ),
                }]

                tool_call_count = 0
                stop_reason = None

                while tool_call_count < MAX_AGENT_TOOLS:
                    response = client.messages.create(
                        model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                        max_tokens=4096,
                        system=_AGENT_SYSTEM,
                        tools=tools,
                        messages=messages,
                    )
                    stop_reason = response.stop_reason
                    messages.append({'role': 'assistant',
                                     'content': response.content})

                    tool_use_blocks = [b for b in response.content
                                       if b.type == 'tool_use']
                    if not tool_use_blocks:
                        break

                    tool_results = []
                    for block in tool_use_blocks:
                        if tool_call_count >= MAX_AGENT_TOOLS:
                            tool_results.append({
                                'type':        'tool_result',
                                'tool_use_id': block.id,
                                'content':     'Budget exhausted — tool execution cancelled.',
                            })
                            continue
                        tool_call_count += 1
                        cmd = block.input.get('command', '')
                        print(f"  [M2:{tool_call_count}] {cmd[:80]}")
                        try:
                            res = await session.call_tool(
                                block.name, block.input
                            )
                            output = res.content[0].text
                            if output.strip() and not output.startswith('ERROR:'):
                                tool_outputs.append(output)
                        except Exception as exc:
                            output = f"ERROR: {exc}"
                        tool_results.append({
                            'type':        'tool_result',
                            'tool_use_id': block.id,
                            'content':     output,
                        })

                    messages.append({'role': 'user', 'content': tool_results})

                # Try to extract prose from the last assistant message.
                # If the loop ended on a tool call (budget exhausted), force a
                # final synthesis response so the report always has a narrative.
                for block in reversed(messages):
                    if block.get('role') == 'assistant':
                        for b in block.get('content', []):
                            if hasattr(b, 'type') and b.type == 'text' and len(b.text) > 100:
                                analysis_text = b.text
                                break
                        break

                if not analysis_text:
                    print(f"  [M2] Budget exhausted — requesting synthesis...")
                    synth = client.messages.create(
                        model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                        max_tokens=1024,
                        system=_AGENT_SYSTEM,
                        messages=messages + [{
                            'role': 'user',
                            'content': (
                                'Your tool budget is exhausted. Write a concise forensic '
                                'analyst summary (3-5 paragraphs) of what you found: '
                                'suspicious processes, injected memory regions, network '
                                'connections, credential access, and persistence. '
                                'Cite specific PIDs, addresses, or registry keys. '
                                'Do not call any more tools.'
                            ),
                        }],
                    )
                    for b in synth.content:
                        if hasattr(b, 'type') and b.type == 'text':
                            analysis_text = b.text
                            break

                elapsed2 = (datetime.now(timezone.utc) - t2).total_seconds()
                print(f"\n  Memory Pass 2 complete: {tool_call_count} calls, "
                      f"{elapsed2:.0f}s")

                final_score, final_hits, final_reasons = \
                    parse_memory_findings(tool_outputs)
                pass_info['pass2_ran']   = True
                pass_info['pass2_calls'] = tool_call_count

    save_memory_report(
        host, memory_path, final_score, final_hits, final_reasons,
        tool_outputs, analysis_text, pass_info,
    )
    return final_score, final_hits


# ── Cross-layer investigation entry point ─────────────────────────────────────
# Used by investigate.py on the future/cross-layer-verification branch.
# Returns LayerClaim list for cross_verifier.py, not the (score, hits) tuple.

_LAYERED_SYSTEM = """\
You are the Memory Investigation Agent. You have access to Volatility 3 only.
Your job: investigate this memory image and identify attacker activity.

Focus on:
- Process injection (windows.malfind — PAGE_EXECUTE_READWRITE regions)
- Suspicious processes (windows.psscan — hidden/unlinked)
- Network connections (windows.netscan — ESTABLISHED connections)
- Credential access (windows.hashdump, windows.lsadump)
- Command history (windows.cmdline — unusual arguments)

For each confirmed finding, call record_finding with the exact vol.py output
that supports it. Do not include techniques you only inferred.
"""

# Same schema as disk_agent._RECORD_FINDING_TOOL — kept in sync manually.
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
                'description': 'MITRE ATT&CK ID, e.g. T1055',
            },
            'technique_name': {'type': 'string'},
            'tool_name': {
                'type': 'string',
                'description': 'The vol.py plugin that produced the evidence',
            },
            'tool_output': {
                'type': 'string',
                'description': (
                    'Exact vol.py output — copy verbatim, do not paraphrase.'
                ),
            },
            'artifact_hint': {
                'type': 'string',
                'description': (
                    'One-line pointer for the verifier: process name, PID, '
                    'address, or plugin. E.g. "MsMpEng.exe PID 1234 PAGE_EXECUTE_READWRITE"'
                ),
            },
        },
        'required': [
            'technique_id', 'technique_name', 'tool_name',
            'tool_output', 'artifact_hint',
        ],
    },
}


async def investigate_layered(
    memory_path: str,
    host: str,
) -> 'list':  # list[LayerClaim] — import deferred to avoid circular
    """
    Memory investigation producing LayerClaim list for same-layer + cross-layer verification.
    Uses VERITAS_LAYER=memory server — disk tools are structurally unavailable.
    Synthesis uses forced tool_use (record_finding) — no text parsing.
    """
    from contracts import LayerClaim

    client = anthropic.Anthropic()
    server_params = StdioServerParameters(
        command='python3',
        args=[os.path.join(_HERE, 'sift_server.py')],
        env={**os.environ, 'VERITAS_LAYER': 'memory'},
    )

    MAX_CALLS = 20
    print(f"\n{'─'*60}")
    print(f"  MEMORY AGENT  —  {memory_path}")
    print(f"  Tools: memory-only (Volatility 3)")
    print(f"  Budget: {MAX_CALLS} tool calls")
    print(f"{'─'*60}")

    all_tool_outputs: list[dict] = []

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
                    f"Memory image: {memory_path}\n"
                    f"Host: {host}\n"
                    f"Investigate this memory image for attacker activity. "
                    f"Use vol.py plugins systematically. "
                    f"Budget: {MAX_CALLS} tool calls."
                ),
            }]

            tool_count = 0
            while tool_count < MAX_CALLS:
                response = client.messages.create(
                    model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                    max_tokens=2048,
                    system=_LAYERED_SYSTEM,
                    tools=tools,
                    messages=messages,
                )
                messages.append({'role': 'assistant', 'content': response.content})

                tool_blocks = [b for b in response.content if b.type == 'tool_use']
                if not tool_blocks:
                    break

                results_block = []
                for block in tool_blocks:
                    if tool_count >= MAX_CALLS:
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
                    cmd = block.input.get('command', block.name)
                    all_tool_outputs.append({'cmd': cmd, 'output': out})
                    tool_count += 1
                    print(f"  [mem] [{tool_count:02d}] {cmd[:70]}")
                    results_block.append({
                        'type': 'tool_result',
                        'tool_use_id': block.id,
                        'content': out[:3000],
                    })
                messages.append({'role': 'user', 'content': results_block})

            # ── Structured synthesis (forced tool_use — no text parsing) ──
            messages.append({
                'role': 'user',
                'content': (
                    'Investigation complete. For each technique where vol.py returned '
                    'direct evidence, call record_finding once with the exact output. '
                    'Only call it for techniques with concrete memory evidence — '
                    'a VAD record, process entry, network connection, or hash. '
                    'Do not call it for techniques you only inferred.'
                ),
            })
            synthesis = client.messages.create(
                model=os.environ.get('VERITAS_MODEL', 'claude-sonnet-4-6'),
                max_tokens=2048,
                system=_LAYERED_SYSTEM,
                messages=messages,
                tools=[_RECORD_FINDING_TOOL],
                tool_choice={'type': 'any'},
            )

    claims: list[LayerClaim] = []
    for block in synthesis.content:
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
            source_layer='memory',
            tool_name=inp.get('tool_name', 'vol'),
            tool_output=inp.get('tool_output', '')[:2000],
            artifact_hint=inp.get('artifact_hint', '')[:200],
        ))

    # Write audit log
    audit_entry = {
        'agent': 'memory_agent_layered',
        'host': host,
        'generated': datetime.now(timezone.utc).isoformat(),
        'memory_path': memory_path,
        'tool_calls': all_tool_outputs,
        'claims': list(claims),
    }
    audit_path = os.path.join(_REPORTS, f'{host}-memory-agent-log.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(audit_path, 'w') as f:
        json.dump(audit_entry, f, indent=2)

    print(f"\n  Memory agent: {len(claims)} claim(s) from {tool_count} tool calls")
    for c in claims:
        print(f"    {c['technique_id']}  {c['artifact_hint'][:60]}")

    return claims


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Memory Agent — Volatility 3 two-pass analysis'
    )
    parser.add_argument('memory_path', help='Path to raw memory image')
    parser.add_argument('--host', required=True,
                        help='Host label used for report filenames (e.g. nfury)')
    parser.add_argument('--no-synthesis', action='store_true',
                        help='Skip Pass 2 agentic loop (Pass 1 only)')
    args = parser.parse_args()
    asyncio.run(investigate(args.memory_path, args.host, args.no_synthesis))
