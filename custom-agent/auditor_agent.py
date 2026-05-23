#!/usr/bin/env python3
"""
auditor_agent.py -- The Forensic Auditor (The Cynic)

Challenges every Triage Agent finding with bounded MCP tool calls.
Produces a timestamped argumentation transcript used as the primary
submission artifact.

Convergence rules:
  - MAX_CHALLENGES_PER_FINDING: max challenge rounds per technique
  - MAX_TOOLS_PER_CHALLENGE:    max MCP tool calls per round
  - CONFIRMED: Auditor exhausts challenge budget without finding contradiction
  - REFUTED:   Auditor finds positive evidence contradicting the finding

Usage (standalone):
    python3 custom-agent/auditor_agent.py --triage reports/nromanoff-custom-agent-report.json
    python3 custom-agent/auditor_agent.py --triage reports/nfury-custom-agent-report.json --target /mnt/nfury

Called programmatically from investigate.py after blue_agent.py.
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

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

MAX_CHALLENGES_PER_FINDING = 3
MAX_TOOLS_PER_CHALLENGE    = 2

_CYNIC_SYSTEM = """\
You are The Forensic Auditor (The Cynic) — a second-opinion agent in a
digital forensics investigation. The Triage Agent has flagged ATT&CK
techniques. Your job is to independently verify each finding using raw
SIFT forensic tool output — not the typed tool summaries the Triage Agent
already produced.

Rules:
1. String-match alone is not proof. Find the definitive physical artifact.
2. Use run_terminal_command to run targeted SIFT CLI commands directly on
   the mounted image. Preferred commands for verification:
     - find /mnt/host -iname 'artifact.exe' 2>/dev/null
     - strings /path/to/binary 2>/dev/null | head -60
     - grep -ac 'ioc_string' /path/to/hive
     - md5sum /path/to/suspicious/file
     - grep -r 'RunKey_value' /path/to/NTUSER.DAT
   Call run_terminal_command first. Only fall back to typed tools if a raw
   command cannot answer the question.
3. Call 1-2 tools to check. Evaluate ALL tool results before deciding.
4. Deliver your verdict:
   - CONFIRMED: credible forensic evidence of this technique exists on this
     host — even if the specific named tool/binary is absent, CONFIRM if you
     find any other artifact consistent with the technique (e.g. procdump.exe
     CONFIRMS T1003.001 even if hydrakatz.exe is absent; a PSEXESVC.EXE binary
     CONFIRMS T1569.002 even if no registry entry is found).
   - REFUTED:   use ONLY when you have verified that NO evidence of this
     technique exists — absence of ONE named binary is NOT sufficient. You must
     be confident the technique left no artifacts anywhere on this host. A
     genuine false positive (e.g. a Run-key finding based solely on a process
     name that is not actually in any Run key) qualifies as REFUTED.
   - INCONCLUSIVE: the named artifact is absent but other ambiguous evidence
     exists, or you cannot determine from available tools whether the technique
     was used. Use this when uncertain.
5. End every response with exactly: VERDICT: <CONFIRMED|REFUTED|INCONCLUSIVE>
6. Be specific — cite the exact artifact path or registry value you found.
   Reference the Attack Chain step number (e.g. "Step 3") when your finding
   confirms or refutes a specific row in the Triage Agent's Attack Chain table.
7. Write in plain prose. One short paragraph per verdict. No extra headers.
"""

_TECHNIQUE_NAMES = {
    'T1547.001': 'Registry Run Key / Boot Autostart',
    'T1036.005': 'Masquerading: Match Legitimate Name',
    'T1003.001': 'OS Credential Dumping: LSASS Memory',
    'T1071.001': 'C2: Application Layer Protocol (Web)',
    'T1569.002': 'System Services: Service Execution (PsExec)',
    'T1087.001': 'Account Discovery: Local Account',
    'T1059':     'Command and Scripting Interpreter',
    'T1059.001': 'Command and Scripting: PowerShell',
    'T1560.001': 'Archive Collected Data: Archive via Utility',
    'T1548.002': 'Abuse Elevation: Bypass UAC',
    'T1055':     'Process Injection',
    'T1056.001': 'Input Capture: Keylogging',
    'T1189':     'Drive-by Compromise',
    'T1204.002': 'User Execution: Malicious File',
    'T1136':     'Create Account',
    'T1136.001': 'Create Account: Local Account',
    'T1078':     'Valid Accounts',
    'T1560':     'Archive Collected Data',
    'T1041':     'Exfiltration Over C2 Channel',
    'T1053.002': 'Scheduled Task: AT',
    'T1021.002': 'Remote Services: SMB / Windows Admin Shares',
}


class ForensicAuditor:
    """
    The Cynic: challenges Triage findings, produces argumentation transcript.
    """

    def __init__(self):
        self.client = anthropic.Anthropic()

    # ── Public entry point ─────────────────────────────────────────────────

    async def audit(self, target_path: str, triage_report: dict,
                    memory_path: str = None) -> tuple:
        """
        Audit all Triage findings in parallel — each technique gets its own
        MCP session so challenges run concurrently.

        Returns:
            confirmed (list[str])   — technique IDs that survived challenge
            refuted   (list[str])   — technique IDs disproved or weakened
            transcript (list[dict]) — full argumentation log (input order)
            adjusted_score (int)    — sum of confirmed technique weights
        """
        host             = os.path.basename(target_path.rstrip('/'))
        triage_score     = triage_report.get('confidence_score', 0)
        techniques       = triage_report.get('techniques_detected', [])
        matched_sigs     = triage_report.get('matched_signals', {})
        technique_sources = triage_report.get('technique_sources', {})
        rules            = self._load_rules()

        print(f"\n{'═'*60}")
        print(f"  FORENSIC AUDITOR  —  {target_path}")
        print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
        print(f"  Challenging {len(techniques)} finding(s) in parallel")
        print(f"  Budget: {MAX_CHALLENGES_PER_FINDING} rounds × "
              f"{MAX_TOOLS_PER_CHALLENGE} tools each")
        print(f"{'═'*60}")

        # asyncio.Lock serialises console output across concurrent coroutines.
        print_lock = asyncio.Lock()

        # Run all technique audits concurrently; each spawns its own sift_server.
        results = await asyncio.gather(*[
            self._audit_finding(
                target_path,
                finding_id,
                matched_sigs.get(finding_id, []),
                rules,
                print_lock,
                source=technique_sources.get(finding_id, 'disk'),
                memory_path=memory_path,
            )
            for finding_id in techniques
        ])

        confirmed     = [r['finding_id'] for r in results if r['final_verdict'] == 'CONFIRMED']
        inconclusive  = [r['finding_id'] for r in results if r['final_verdict'] == 'INCONCLUSIVE']
        refuted       = [r['finding_id'] for r in results if r['final_verdict'] == 'REFUTED']
        transcript    = list(results)

        # Adjusted score = sum of confirmed weights, capped at 100.
        adjusted_score = min(
            sum(rules.get(tid, {}).get('weight', 35) if rules else 35
                for tid in confirmed),
            100,
        )

        output = {
            'generated':              datetime.now(timezone.utc).isoformat(),
            'target':                 target_path,
            'triage_score':           triage_score,
            'triage_techniques':      techniques,
            'audited_count':          len(techniques),
            'confirmed_count':        len(confirmed),
            'inconclusive_count':     len(inconclusive),
            'refuted_count':          len(refuted),
            'adjusted_score':         adjusted_score,
            'convergence':            'all_findings_processed',
            'confirmed_findings':     confirmed,
            'inconclusive_findings':  inconclusive,
            'refuted_findings':       refuted,
            'transcript':             transcript,
        }

        out_path = os.path.join(_REPORTS, f'{host}-auditor-transcript.json')
        os.makedirs(_REPORTS, exist_ok=True)
        with open(out_path, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"\n{'═'*60}")
        print(f"  AUDIT COMPLETE")
        print(f"  Triage score:    {triage_score}")
        print(f"  Confirmed:       {len(confirmed)}  {confirmed}")
        print(f"  Inconclusive:    {len(inconclusive)}  {inconclusive}")
        print(f"  Refuted:         {len(refuted)}  {refuted}")
        print(f"  Adjusted score:  {adjusted_score}")
        print(f"  Transcript  ->   {out_path}")
        print(f"{'═'*60}\n")

        return confirmed, inconclusive, refuted, transcript, adjusted_score

    # ── Per-finding coroutine (one MCP session each) ──────────────────────

    async def _audit_finding(
        self,
        target_path: str,
        finding_id: str,
        signals: list,
        rules: dict,
        print_lock: asyncio.Lock,
        source: str = 'disk',
        memory_path: str = None,
    ) -> dict:
        """
        Audit a single finding with its own MCP session.
        Called concurrently via asyncio.gather — each spawns sift_server.py.
        """
        finding_name = self._technique_name(finding_id, rules)
        weight       = rules.get(finding_id, {}).get('weight', 35) if rules else 35
        signal_tier  = self._signal_tier(finding_id, signals, rules)

        server_params = StdioServerParameters(
            command='python3',
            args=[os.path.join(_HERE, 'sift_server.py')],
        )

        async with print_lock:
            print(f"\n  ── {finding_id} ({finding_name}) ──")
            print(f"     Signals: {signals}  [tier: {signal_tier}]")

        challenge_history = []
        final_verdict     = 'INCONCLUSIVE'   # requires positive evidence to become CONFIRMED
        convergence       = 'budget_exhausted'
        any_confirmed     = False

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = self._list_tools(await session.list_tools())

                for rnd in range(1, MAX_CHALLENGES_PER_FINDING + 1):
                    async with print_lock:
                        print(f"     [{finding_id}] Round {rnd}/{MAX_CHALLENGES_PER_FINDING} ...",
                              end='', flush=True)

                    verdict, reasoning, tools_called, raw_output = \
                        await self._challenge_round(
                            session, tools,
                            finding_id, finding_name, signals,
                            target_path, challenge_history,
                            signal_tier=signal_tier,
                            source=source,
                            memory_path=memory_path,
                        )

                    challenge_history.append({
                        'round':        rnd,
                        'tools_called': tools_called,
                        'tool_output':  raw_output[:4000],
                        'verdict':      verdict,
                        'reasoning':    reasoning,
                    })

                    async with print_lock:
                        print(f" {verdict}")
                        words, line = reasoning.split(), []
                        for word in words:
                            if sum(len(w)+1 for w in line) + len(word) > 76:
                                print(f"       {''.join(w+' ' for w in line).rstrip()}")
                                line = [word]
                            else:
                                line.append(word)
                        if line:
                            print(f"       {''.join(w+' ' for w in line).rstrip()}")

                    if verdict == 'CONFIRMED':
                        any_confirmed = True
                        convergence   = f'positive_evidence_round_{rnd}'
                    elif verdict == 'REFUTED':
                        final_verdict = 'REFUTED'
                        convergence   = f'contradiction_round_{rnd}'
                        break

        if final_verdict != 'REFUTED':
            if any_confirmed:
                final_verdict = 'CONFIRMED'
            else:
                final_verdict = 'INCONCLUSIVE'
                convergence   = 'budget_exhausted_no_positive_evidence'

        async with print_lock:
            if final_verdict == 'CONFIRMED':
                print(f"     [{finding_id}] => CONFIRMED (positive evidence found)")
            elif final_verdict == 'REFUTED':
                print(f"     [{finding_id}] => REFUTED   (removed from adjusted score)")
            else:
                domain = 'memory' if source == 'memory' else 'disk'
                print(f"     [{finding_id}] => INCONCLUSIVE "
                      f"(artifact not located in {domain})")

        return {
            'finding_id':         finding_id,
            'finding_name':       finding_name,
            'triage_signals':     signals,
            'triage_weight':      weight,
            'source':             source,
            'challenges':         challenge_history,
            'final_verdict':      final_verdict,
            'convergence_reason': convergence,
        }

    # ── Challenge loop ─────────────────────────────────────────────────────

    async def _challenge_round(
        self, session, tools: list,
        finding_id: str, finding_name: str, triage_signals: list,
        target_path: str, prior_challenges: list,
        signal_tier: str = 'mixed',
        source: str = 'disk',
        memory_path: str = None,
    ) -> tuple:
        """
        One bounded challenge round (≤ MAX_TOOLS_PER_CHALLENGE tool calls).
        Returns (verdict, reasoning, tools_called, combined_output).
        """
        prior_summary = '\n'.join(
            f"  Round {c['round']} [{c['verdict']}]: {c['reasoning'][:80]}"
            for c in prior_challenges
        ) if prior_challenges else '  (none)'

        if signal_tier == 'forensic_ioc':
            tier_guidance = (
                'These signals are forensically-verified IOCs. '
                'Use run_terminal_command to locate the physical artifact on disk: '
                f'find {target_path} -iname \'<ioc_name>\' 2>/dev/null  '
                'or  strings /path/to/binary | head -50  '
                'or  md5sum /path/to/file  to verify the hash.'
            )
        elif signal_tier == 'asl_trained':
            tier_guidance = (
                'These signals are ASL-trained behavioral patterns from Sysmon events. '
                'Use run_terminal_command to find corroborating disk artifacts: '
                f'find {target_path} -iname \'*.pf\' 2>/dev/null | grep -i <binary>  '
                '(Prefetch execution evidence)  or  '
                f'grep -r \'RunKey_pattern\' {target_path}/WINDOWS/system32/config/  '
                '(registry persistence).'
            )
        else:
            tier_guidance = (
                'These signals are a mix of ASL-trained and forensic IOC tiers. '
                'Use run_terminal_command: find for IOC artifacts by name, '
                'strings on suspicious binaries, grep on registry hives.'
            )

        # Source-aware verification guidance
        if source == 'memory' and memory_path:
            source_guidance = (
                f"This finding came from MEMORY analysis (Volatility 3). "
                f"Verify using vol.py against the memory image:\n"
                f"  vol.py -q -f {memory_path} windows.malfind 2>/dev/null\n"
                f"  vol.py -q -f {memory_path} windows.cmdline 2>/dev/null\n"
                f"  vol.py -q -f {memory_path} windows.netscan 2>/dev/null\n"
                f"  vol.py -q -f {memory_path} windows.hashdump 2>/dev/null\n"
                f"Also cross-check on disk: find {target_path} -iname '<artifact>' 2>/dev/null"
            )
        elif source == 'disk+memory' and memory_path:
            source_guidance = (
                f"This finding was corroborated in BOTH disk and memory. "
                f"Confirm with disk SIFT commands on {target_path} "
                f"AND vol.py -q -f {memory_path} <plugin> 2>/dev/null. "
                f"Corroboration across both domains raises confidence significantly."
            )
        else:
            source_guidance = (
                f"This finding came from DISK analysis. "
                f"Verify using SIFT commands on the mounted image at {target_path}."
            )

        messages = [{
            'role': 'user',
            'content': (
                f"Target image: {target_path}\n"
                f"Finding: {finding_id} ({finding_name})\n"
                f"Source: {source}\n"
                f"Triage matched signals: {triage_signals}\n"
                f"Signal tier: {signal_tier}. {tier_guidance}\n"
                f"{source_guidance}\n"
                f"Prior challenge rounds:\n{prior_summary}\n\n"
                f"Challenge this finding with run_terminal_command. "
                f"Use vol.py for memory artifacts, SIFT commands for disk artifacts. "
                f"Call up to {MAX_TOOLS_PER_CHALLENGE} "
                f"tools to PROVE or DISPROVE this technique was used on this host. "
                f"End with: VERDICT: <CONFIRMED|REFUTED|INCONCLUSIVE>"
            ),
        }]

        tools_called  = []
        tool_outputs  = []
        tools_used    = 0

        while True:
            response = self.client.messages.create(
                model='claude-opus-4-5',
                max_tokens=1024,
                system=_CYNIC_SYSTEM,
                messages=messages,
                tools=tools,
            )

            if response.stop_reason == 'tool_use':
                tool_results = []
                messages.append({'role': 'assistant', 'content': response.content})

                for block in response.content:
                    if block.type != 'tool_use':
                        continue
                    if tools_used >= MAX_TOOLS_PER_CHALLENGE:
                        # Silently signal budget exhaustion without raising an error
                        tool_results.append({
                            'type':        'tool_result',
                            'tool_use_id': block.id,
                            'content':     '[TOOL BUDGET EXHAUSTED — no further calls this round]',
                        })
                        continue
                    try:
                        result = await session.call_tool(block.name, block.input)
                        output = result.content[0].text
                    except Exception as exc:
                        output = f'[Tool error: {exc}]'

                    cmd_str = block.input.get('command', block.name)
                    tools_called.append(cmd_str)
                    tool_outputs.append(output)
                    tools_used += 1
                    tool_results.append({
                        'type':        'tool_result',
                        'tool_use_id': block.id,
                        'content':     output[:2000],
                    })

                messages.append({'role': 'user', 'content': tool_results})

            else:
                # Claude gave a text verdict
                text      = response.content[0].text if response.content else ''
                verdict   = self._parse_verdict(text)
                reasoning = self._extract_reasoning(text)
                combined  = '\n---\n'.join(tool_outputs)
                return verdict, reasoning, tools_called, combined

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _list_tools(mcp_tools) -> list:
        return [
            {'name': t.name, 'description': t.description,
             'input_schema': t.inputSchema}
            for t in mcp_tools.tools
        ]

    @staticmethod
    def _load_rules() -> dict:
        path = os.path.join(_REPORTS, 'operational_rules.json')
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f).get('rules', {})
        return {}

    @staticmethod
    def _technique_name(tid: str, rules: dict) -> str:
        if rules and tid in rules and 'name' in rules[tid]:
            return rules[tid]['name']
        return _TECHNIQUE_NAMES.get(tid, tid)

    @staticmethod
    def _parse_verdict(text: str) -> str:
        upper = text.upper()
        for line in upper.splitlines():
            line = line.strip()
            if line.startswith('VERDICT:'):
                if 'REFUTED'       in line: return 'REFUTED'
                if 'CONFIRMED'     in line: return 'CONFIRMED'
                if 'INCONCLUSIVE'  in line: return 'INCONCLUSIVE'
        # Fallback: scan full text
        if 'VERDICT: REFUTED'      in upper: return 'REFUTED'
        if 'VERDICT: CONFIRMED'    in upper: return 'CONFIRMED'
        if 'VERDICT: INCONCLUSIVE' in upper: return 'INCONCLUSIVE'
        return 'INCONCLUSIVE'

    @staticmethod
    def _extract_reasoning(text: str) -> str:
        lines = [l.strip() for l in text.splitlines()
                 if l.strip() and not l.strip().upper().startswith('VERDICT:')]
        return ' '.join(lines)  # full reasoning stored; CLI truncates for display

    @staticmethod
    def _signal_tier(finding_id: str, matched_signals: list, rules: dict) -> str:
        if not rules or finding_id not in rules:
            return 'unknown'
        tagged = rules[finding_id].get('signals_tagged', [])
        tiers = {t['tier'] for t in tagged if t['signal'] in matched_signals}
        if not tiers:
            return 'unknown'
        if tiers == {'forensic_ioc'}:
            return 'forensic_ioc'
        if tiers == {'asl_trained'}:
            return 'asl_trained'
        return 'mixed'


# ── Standalone entry point ─────────────────────────────────────────────────

async def _main():
    parser = argparse.ArgumentParser(
        description='Forensic Auditor — challenges Triage findings with '
                    'bounded MCP tool calls'
    )
    parser.add_argument('--triage', required=True,
                        help='Path to triage report JSON (from blue_agent.py)')
    parser.add_argument('--target',
                        help='Override mount path (default: from triage report)')
    args = parser.parse_args()

    if not os.path.exists(args.triage):
        print(f"ERROR: Triage report not found: {args.triage}")
        sys.exit(1)

    with open(args.triage) as f:
        triage_report = json.load(f)

    target = args.target or triage_report.get('target', '')
    if not target or not os.path.isdir(target):
        print(f"ERROR: Target not found or not mounted: {target!r}")
        print("  Use --target to override the mount path from the triage report.")
        sys.exit(1)

    auditor = ForensicAuditor()
    await auditor.audit(target, triage_report)


if __name__ == '__main__':
    asyncio.run(_main())
