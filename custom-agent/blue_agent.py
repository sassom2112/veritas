import anthropic
import argparse
import asyncio
import json
import logging
import re
import os
import sys
from datetime import datetime, timezone
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('mcp').setLevel(logging.WARNING)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sift_server import windows_dir, system32_dir, config_dir, profiles_dir, config_hive

_REPORTS   = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
_DATA_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
_CAL_PATH  = os.path.join(_DATA_DIR, 'calibrated_weights.json')

# Load calibrated signal weights produced by compute_weights.py (empty dict if not yet built)
_CAL_WEIGHTS: dict = {}
if os.path.exists(_CAL_PATH):
    try:
        with open(_CAL_PATH) as _f:
            _CAL_WEIGHTS = json.load(_f)
        print(f"🎯 Calibrated weights loaded ({len(_CAL_WEIGHTS)} techniques)")
    except Exception as _e:
        print(f"⚠️  calibrated_weights.json unreadable: {_e}")

KNOWN_IOCS = {
    'c2_ips': ['12.190.135.235', '199.73.28.114'],
    'c2_paths': ['/ads/'],
    'persistence': ['dllhost\\svchost.exe run key', 'psexesvc'],
    'tools': ['spinlock.exe', 'hythonize.exe', 'hythonized.exe'],
    'hashes': {'spinlock.exe': '6bff2aebb8852fc2658b9768d2166ece'},
    'anti_forensics': ['BCWipe'],
    'exfil_archives': ['system4.rar'],
    'accounts': [{'name': 'vibranium', 'sid': '-1673'}],
}

_PROTECTED_SIGNALS = [
    'psexesvc', 'psexec', 'mimikatz', 'hydrakatz',
    'lsass', '0x1fffff', 'dllhost\\\\svchost',
    '12.190.135.235', '199.73.28.114', 'winclient',
    'sekurlsa', 'spinlock', 'system4.rar',
    'eventid=7045', 'sc.exe create', '\\admin$\\',
    'invoke-expression', 'powershell -enc',
    'fodhelper', 'net user /domain', 'samr',
    'record_mic', 'audiocapture',
]

# Pass 2 configuration
MAX_AGENT_TOOLS = 75
CHECKPOINT_AT   = 25   # pause for operator review after this many calls

_audit_log = []


def _audit(tool_name, command, result_snippet, usage=None):
    _audit_log.append({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'tool': tool_name,
        'command': command,
        'result_preview': result_snippet[:120],
        'tokens_used': usage.input_tokens + usage.output_tokens if usage else None,
    })


def _extract_pass2_techniques(client, analysis_text: str) -> dict:
    """
    Extract ATT&CK technique IDs from Pass 2 prose analysis.
    Returns {technique_id: [signal_strings]}.

    Two-stage: regex harvest (never fails) + LLM for richer signal extraction.
    LLM failure falls back to regex harvest so no technique is silently dropped.
    """
    if not analysis_text.strip():
        return {}

    # Stage 1 — direct regex harvest: any T####.### or T#### in the prose
    regex_hits: dict = {}
    for m in re.finditer(r'\b(T\d{4}(?:\.\d{3})?)\b', analysis_text):
        tid = m.group(1)
        if tid not in regex_hits:
            start   = max(0, m.start() - 80)
            end     = min(len(analysis_text), m.end() + 160)
            context = analysis_text[start:end].strip().replace('\n', ' ')
            regex_hits[tid] = [context[:100]]

    # Stage 2 — LLM extraction for structured signals
    prompt = (
        "You are a forensic analyst. Extract every distinct ATT&CK technique "
        "mentioned in the forensic analysis below. For each technique, list the "
        "key artifact names or strings (filenames, hashes, account names, IPs, "
        "registry values) that were found as evidence.\n\n"
        "Return ONLY a valid JSON array. No prose, no markdown, no explanation.\n"
        "Format: [{\"id\": \"T1136\", \"name\": \"Create Account\", "
        "\"signals\": [\"vibranium\", \"SAM hive\"]}]\n\n"
        f"Analysis:\n{analysis_text[:4000]}"
    )
    try:
        resp = client.messages.create(
            model='claude-haiku-4-5-20251001',
            max_tokens=1024,
            messages=[{'role': 'user', 'content': prompt}],
        )
        raw = resp.content[0].text.strip()
        if raw.startswith('```'):
            raw = '\n'.join(raw.split('\n')[1:])
            raw = raw.rsplit('```', 1)[0].strip()
        techniques = json.loads(raw)
        llm_hits = {t['id']: t.get('signals', []) for t in techniques if 'id' in t}
        # Merge: LLM takes precedence; regex fills any gaps LLM missed
        for tid, sigs in regex_hits.items():
            if tid not in llm_hits:
                llm_hits[tid] = sigs
        return llm_hits
    except Exception as exc:
        print(f"  [P2-extract] LLM failed ({exc}) — using regex harvest "
              f"({len(regex_hits)} techniques)")
        return regex_hits


def _checkpoint(tool_call_count, pass1_hits, tool_outputs, rules):
    """
    Print a status update and optionally ask the operator whether to continue.
    Returns True if the operator wants to stop and generate the report now.
    """
    current_score, current_hits, _ = parse_findings(tool_outputs, rules)
    new_techs = sorted(set(current_hits.keys()) - set(pass1_hits.keys()))
    non_empty = sum(1 for o in tool_outputs if o.strip())

    print(f"\n{'━'*60}")
    print(f"  INVESTIGATION CHECKPOINT  "
          f"({tool_call_count} of {MAX_AGENT_TOOLS} calls used)")
    print(f"{'━'*60}")
    print(f"  Current score:    {current_score}")
    print(f"  Techniques found: {list(current_hits.keys())}")
    if new_techs:
        print(f"  New since Pass 1: {new_techs}")
    print(f"  Non-empty outputs: {non_empty}")
    print(f"  Budget remaining:  {MAX_AGENT_TOOLS - tool_call_count} calls")
    print(f"{'━'*60}")

    if sys.stdin.isatty():
        print("  Continuing gathers: hashes, MAC timestamps, strings,")
        print("  event log entries, prefetch execution times, LSA secrets.")
        print()
        print("  [Enter / C]  Continue deep investigation")
        print("  [R]          Generate report now with current findings")
        try:
            choice = input("  > ").strip().lower()
            return choice == 'r'
        except (EOFError, KeyboardInterrupt):
            return False
    else:
        print("  (non-interactive — continuing automatically)")
        return False


def save_findings_report(target, score, level, hits, reasons,
                         tool_outputs, analysis_text, rules,
                         pass_info=None, pass2_tool_log=None):
    host = os.path.basename(target.rstrip('/'))
    path = os.path.join(_REPORTS, f'{host}-custom-agent-report.json')

    asl_iteration = None
    rules_file = os.path.join(_REPORTS, 'operational_rules.json')
    if os.path.exists(rules_file):
        with open(rules_file) as f:
            asl_iteration = json.load(f).get('trained_iterations')

    report = {
        'generated': datetime.now(timezone.utc).isoformat(),
        'target': target,
        'agent': 'triage-agent',
        'asl_iteration': asl_iteration,
        'rules_loaded': bool(rules),
        'two_pass_scan': pass_info,
        'confidence_score': score,
        'confidence_level': level,
        'techniques_detected': list(hits.keys()),
        'detection_reasons': reasons,
        'matched_signals': hits,
        'tool_outputs_count': len(tool_outputs),
        'claude_analysis': analysis_text,
        'pass2_tool_log': pass2_tool_log or [],
    }

    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Report saved → {path}")


def save_audit_log(path=None):
    if path is None:
        host = os.path.basename(os.environ.get('BLUE_TARGET', 'unknown').rstrip('/'))
        path = os.path.join(_REPORTS, f'audit_log_{host}.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(_audit_log, f, indent=2)
    print(f"\n📋 Audit log saved → {path} ({len(_audit_log)} entries)")


def load_operational_rules(rules_path=None):
    if rules_path is None:
        rules_path = os.path.join(_REPORTS, 'operational_rules.json')
    if os.path.exists(rules_path):
        with open(rules_path) as f:
            data = json.load(f)
        rules = data.get('rules', {})
        iterations = data.get('trained_iterations', 0)
        print(f"🧠 Loaded {len(rules)} ASL-trained rules "
              f"(from iteration {iterations})")
        return rules
    print("⚠️  No trained rules found — using base IOC patterns")
    return None


# ── Scoring Engine ───────────────────────────────────────────────
BASE_PATTERNS = {
    'T1547.001': {
        'name': 'Registry Run Key',
        'signals': ['currentversion\\run', 'runonce', 'dllhost\\svchost'],
        'weight': 35,
    },
    'T1036.005': {
        'name': 'Masquerading',
        'signals': ['102400', 'dllhost\\svchost.exe'],
        'weight': 35,
    },
    'T1003.001': {
        'name': 'Credential Dumping',
        'signals': ['hydrakatz', 'lsass', 'mimikatz', 'sekurlsa'],
        'weight': 35,
    },
    'T1071.001': {
        'name': 'C2 Web Protocol',
        'signals': ['12.190.135.235', '199.73.28.114', 'winclient'],
        'weight': 35,
    },
    'T1569.002': {
        'name': 'PsExec',
        'signals': ['psexesvc', 'psexec', '\\admin$\\'],
        'weight': 35,
    },
    'T1087.001': {
        'name': 'Account Discovery',
        'signals': ['net user /domain', 'seatbelt', 'enumdomainusers',
                    'net localgroup', 'getdomaingroup'],
        'weight': 25,
    },
    'T1059.001': {
        'name': 'PowerShell / VBS Execution',
        'signals': ['wscript.exe', 'cscript.exe', 'powershell -enc',
                    'invoke-expression', 'sharpview', 'netsh advfirewall'],
        'weight': 25,
    },
    'T1560.001': {
        'name': 'Archive Collected Data',
        'signals': ['record_mic', '7z.exe', 'rar.exe', 'audiocapture'],
        'weight': 25,
    },
    'T1548.002': {
        'name': 'UAC Bypass',
        'signals': ['fodhelper', 'eventvwr.exe', 'sdclt.exe',
                    'integritylevel=high', 'fax service'],
        'weight': 30,
    },
}


def _signal_matches(sig: str, text: str) -> bool:
    """Precise match: word boundaries for short single tokens, substring for everything else."""
    sig_norm = sig.lower().replace('\\\\', '\\')
    # Short single-word tokens (≤8 chars, no spaces) require word boundaries
    # to prevent "net" matching "network", "reg" matching "registry", etc.
    if ' ' not in sig_norm and len(sig_norm) <= 8:
        return bool(re.search(r'\b' + re.escape(sig_norm) + r'\b', text))
    return sig_norm in text


def parse_findings(tool_outputs, rules=None):
    safe_outputs = [o for o in tool_outputs if 'ANTHROPIC_API_KEY' not in o]
    text = ' '.join(safe_outputs).lower().replace('\\\\', '\\')

    patterns = rules if rules else BASE_PATTERNS
    score = 0
    hits = {}
    reasons = []

    for technique_id, data in patterns.items():
        matched = [s for s in data['signals'] if _signal_matches(s, text)]
        if not matched:
            continue

        # Calibrated per-signal weights (from compute_weights.py) take priority
        cal = _CAL_WEIGHTS.get(technique_id, {})
        sig_weights = cal.get('signals', {})
        if sig_weights:
            # Each signal contributes proportionally to its discriminative power
            raw = sum(sig_weights.get(s.lower(), 0.1) * 100 for s in matched)
            weight = min(int(raw), cal.get('base_weight', data['weight']))
        elif len(matched) >= 2:
            weight = data['weight']
        else:
            weight = data['weight'] // 2

        if weight > 0:
            if rules:
                tagged = {t['signal']: t['tier']
                          for t in data.get('signals_tagged', [])}
                tiers = {tagged.get(s, 'asl_trained') for s in matched}
                if tiers == {'forensic_ioc'}:
                    source = '[IOC]'
                elif 'forensic_ioc' in tiers:
                    source = '[ASL+IOC]'
                else:
                    source = '[ASL]'
            else:
                source = '[base]'
            score += weight
            hits[technique_id] = matched
            reasons.append(
                f"{data['name']} (+{weight}) {source} via: {matched}"
            )

    return min(score, 100), hits, reasons


# ── Pass 1 scan command builders ─────────────────────────────────────────────

def _build_scan_commands(mount: str) -> list[tuple[str, str]]:
    """
    Generic TTP-based Pass 1 sweep — no case-specific IOCs.
    """
    win  = windows_dir(mount)
    prof = profiles_dir(mount)
    sw   = config_hive(mount, 'SOFTWARE')
    sys_ = config_hive(mount, 'SYSTEM')
    sam  = config_hive(mount, 'SAM')

    return [
        ('reg_run_rip',
         f"rip.pl -r '{sw}' -f run 2>/dev/null"),
        ('reg_run_strings',
         f"strings -e l '{sw}' 2>/dev/null | grep -iA3 'CurrentVersion.Run' | head -60"),
        ('reg_run_ntuser',
         f"find '{prof}' -maxdepth 2 -name 'NTUSER.DAT' 2>/dev/null "
         f"| xargs -I{{}} rip.pl -r {{}} -f run 2>/dev/null | head -80"),
        ('scheduled_tasks',
         f"find '{win}' -path '*/Tasks/*' -name '*.xml' 2>/dev/null | head -20 || "
         f"find '{win}' -name '*.job' 2>/dev/null | head -20"),
        ('services_unusual',
         f"rip.pl -r '{sys_}' -f services 2>/dev/null | grep -iv "
         f"'system32\\|syswow64\\|sysWOW64\\|Program Files\\|Windows\\\\' | head -40"),
        ('cred_tools_find',
         f"find '{mount}' -iname 'mimikatz*' -o -iname 'procdump*' "
         f"-o -iname 'wce.exe' -o -iname 'pwdump*' -o -iname 'gsecdump*' "
         f"-o -iname 'fgdump*' "
         f"2>/dev/null | head -15"),
        ('lsass_dump',
         f"find '{mount}' -iname '*.dmp' 2>/dev/null | grep -i lsass | head -5"),
        ('sam_users',
         f"strings '{sam}' 2>/dev/null | grep -Ei '^[A-Za-z][A-Za-z0-9_.-]{{2,19}}$' "
         f"| grep -iv 'microsoft\\|windows\\|system\\|local\\|network\\|builtin' | head -30"),
        ('psexec_binary',
         f"find '{win}' -maxdepth 1 -iname 'PSEXESVC.EXE' 2>/dev/null"),
        ('psexec_registry',
         f"rip.pl -r '{sys_}' -f services 2>/dev/null | grep -i 'PSEXESVC\\|psexec' | head -20"),
        ('admin_share_artifacts',
         f"find '{win}' -name 'Prefetch' -prune -o "
         f"-name '*.exe' -newer '{win}/explorer.exe' -print 2>/dev/null | head -10"),
        ('user_profiles',
         f"find '{prof}' -maxdepth 1 -type d 2>/dev/null"),
        ('local_accounts',
         f"rip.pl -r '{sam}' -f samparse 2>/dev/null | head -60"),
        ('svchost_masquerade',
         f"find '{mount}' -name 'svchost.exe' "
         f"! -path '*/System32/*' ! -path '*/system32/*' "
         f"! -path '*/SysWOW64/*' 2>/dev/null | head -10"),
        ('system32_lookalikes',
         f"find '{mount}' -maxdepth 4 -name 'lsass.exe' -o -name 'csrss.exe' "
         f"-o -name 'winlogon.exe' -o -name 'services.exe' 2>/dev/null "
         f"| grep -v '{win}' | head -10"),
        ('exe_appdata',
         f"find '{prof}' -name '*.exe' "
         f"-path '*/Application Data/*' 2>/dev/null | head -15"),
        ('exe_appdata_win7',
         f"find '{prof}' -name '*.exe' "
         f"-path '*/AppData/*' 2>/dev/null | head -15"),
        ('exe_temp',
         f"find '{prof}' -name '*.exe' -path '*/Temp/*' 2>/dev/null | head -15"),
        ('exe_recycler',
         f"find '{mount}' -ipath '*/$Recycle.Bin*' -name '*.exe' 2>/dev/null | head -10 || "
         f"find '{mount}' -ipath '*/RECYCLER/*' -name '*.exe' 2>/dev/null | head -10"),
        ('prefetch',
         f"find '{win}/Prefetch' -name '*.pf' 2>/dev/null | head -60 || "
         f"find '{win}/prefetch' -name '*.pf' 2>/dev/null | head -60"),
        ('ps1_scripts',
         f"find '{mount}' -name '*.ps1' 2>/dev/null | head -10"),
        ('vbs_scripts',
         f"find '{mount}' -name '*.vbs' -o -name '*.wsf' 2>/dev/null | head -10"),
        ('archives',
         f"find '{mount}' -iname '*.rar' -o -iname '*.7z' -o -iname '*.zip' "
         f"2>/dev/null | grep -iv 'Windows\\|Program Files\\|install' | head -10"),
        ('event_logs',
         f"find '{mount}' -iname '*.evtx' -o -iname '*.Evt' 2>/dev/null | head -20"),
    ]


def _build_ioc_commands(mount: str, ioc_data: dict) -> list[tuple[str, str]]:
    cmds = []
    prof = profiles_dir(mount)
    sw   = config_hive(mount, 'SOFTWARE')
    sys_ = config_hive(mount, 'SYSTEM')

    c2_ips = ioc_data.get('c2_ips', [])
    if c2_ips:
        ip_pattern = '|'.join(re.escape(ip) for ip in c2_ips)
        cmds.append(('ioc_c2_software',
            f"strings -e l '{sw}' 2>/dev/null | grep -E '{ip_pattern}' | head -10"))
        cmds.append(('ioc_c2_system',
            f"strings -e l '{sys_}' 2>/dev/null | grep -E '{ip_pattern}' | head -10"))

    for key in ioc_data.get('registry_keys', []):
        cmds.append((f'ioc_regkey_{key}',
            f"strings -e l '{sw}' 2>/dev/null | grep -i '{key}' | head -5"))

    for fname in ioc_data.get('filenames', []):
        cmds.append((f'ioc_file_{fname}',
            f"find '{mount}' -iname '{fname}' 2>/dev/null | head -5"))

    for acct in ioc_data.get('accounts', []):
        cmds.append((f'ioc_account_{acct}',
            f"find '{mount}' -iname '*{acct}*' 2>/dev/null | head -5"))

    for dirname in ioc_data.get('directories', []):
        cmds.append((f'ioc_dir_{dirname}',
            f"find '{mount}' -name '{dirname}' -type d 2>/dev/null | head -5"))

    return cmds


# ── Agent Loop ───────────────────────────────────────────────────
async def investigate(target_path, rules=None, no_synthesis=False, ioc_data=None):
    client = anthropic.Anthropic()
    tool_outputs: list[str] = []

    server_params = StdioServerParameters(
        command='python3',
        args=[os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sift_server.py')]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── PASS 1: Raw SIFT command sweep ────────────────────────────
            print("\n── Pass 1: Raw SIFT scan ────────────────────────────────")
            t0 = datetime.now(timezone.utc)

            scan_commands = _build_scan_commands(target_path)
            if ioc_data:
                scan_commands += _build_ioc_commands(target_path, ioc_data)
            for label, cmd in scan_commands:
                try:
                    result = await session.call_tool(
                        'run_terminal_command', {'command': cmd}
                    )
                    output = result.content[0].text
                    _audit('run_terminal_command', cmd, output)
                    if output.strip() and not output.startswith('ERROR:'):
                        tool_outputs.append(output)
                        print(f"  [P1] {label}: {len(output)} bytes")
                    else:
                        print(f"  [P1] {label}: (empty)")
                except Exception as exc:
                    print(f"  [P1] {label} error: {exc}")

            pass1_score, pass1_hits, pass1_reasons = parse_findings(tool_outputs, rules)
            elapsed1 = (datetime.now(timezone.utc) - t0).total_seconds()
            print(f"\n  Score: {pass1_score}  ({elapsed1:.1f}s)")
            for r in pass1_reasons:
                print(f"    • {r}")

            final_score   = pass1_score
            final_hits    = pass1_hits
            final_reasons = pass1_reasons
            analysis_text = ''
            pass2_tool_log: list[dict] = []
            pass_info: dict = {
                'pass1_score': pass1_score,
                'pass1_hits':  list(pass1_hits.keys()),
                'pass2_ran':   False,
            }

            # ── PASS 2: Agentic investigation loop ────────────────────────
            if no_synthesis or pass1_score < 5:
                skip_reason = '--no-synthesis' if no_synthesis else f'low confidence (score={pass1_score})'
                print(f"\n── Pass 2 skipped ({skip_reason}) ────────────────────────")
            else:
                print(f"\n── Pass 2: Agentic investigation (budget: {MAX_AGENT_TOOLS} calls) ─────")
                t2 = datetime.now(timezone.utc)

                mcp_tools = await session.list_tools()
                tools = [
                    {'name': t.name, 'description': t.description,
                     'input_schema': t.inputSchema}
                    for t in mcp_tools.tools
                ]

                already_checked = ', '.join(label for label, _ in scan_commands)

                collected = "\n\n---\n".join(
                    f"[P1:{i+1}]:\n{out[:500]}"
                    for i, out in enumerate(tool_outputs)
                )

                _AGENT_SYSTEM = """\
You are an experienced DFIR analyst conducting a full forensic investigation on a SANS \
SIFT workstation. A fast deterministic sweep has already run. Your job is to go deep.

ARTIFACT EXTRACTION DISCIPLINE — apply to every suspicious binary you locate:
  1. md5sum '<full_path>'                              (hash for verification)
  2. stat '<full_path>'                                (exact MAC timestamps)
  3. strings '<full_path>' 2>/dev/null | head -60      (embedded strings / C2 hints)
  4. find '<windir>/Prefetch' -iname '<name>*.pf' 2>/dev/null  (execution evidence)

For every Registry Run key hit: rip.pl to extract full key path + value data + lastwrite time.
For every suspicious account found: grep event logs for EventID 4624 with that username.
For every .dmp file: strings on it, check path and creation timestamp.
For every service flagged: rip.pl -r SYSTEM -f services to get full service entry.

WINDOWS EVENT LOG PARSING (.evtx / .Evt) — use EvtxECmd (in allowlist):
  dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
    -f '<evtx_path>' --csv /tmp/evtx_out --csvf evtx.csv 2>/dev/null
  grep -iE '7045|4624|4625|4688|4720|4776' /tmp/evtx_out/evtx.csv | head -40
Do NOT use evtxexport (not in allowlist) or python3 -c inline code (blocked).
Key Event IDs: 7045=service install, 4624=successful logon, 4625=failed logon,
  4688=process create, 4720=account created, 4776=credential validation.\

Call run_terminal_command with real SIFT CLI commands. Do NOT repeat Pass 1 commands.

FINAL ASSESSMENT — use structured markdown with these two required sections:

## Attack Chain
| Step | Time | Host | User | Technique | Evidence |
|------|------|------|------|-----------|---------|
One row per confirmed event in chronological order. \
Time = exact timestamp from stat or evtx output. \
Evidence = specific artifact that proves this step: exact path, MD5 hash, prefetch entry, or event ID. \
No row without a directly observed artifact.

## MITRE ATT&CK Mapping
| Technique ID | Name | Confidence | Evidence |
|--------------|------|------------|---------|
Evidence column = artifact path, hash, event ID, or prefetch entry directly observed in tool output. \
Confidence = HIGH (artifact + execution proof) / MEDIUM (artifact only) / LOW (indirect signal). \
Never list a technique without citing the raw evidence that supports it. No speculation.\
"""

                uncovered = (
                    "Event log CONTENT (parse .evtx/.Evt — look for 4624/4625 logons, "
                    "7045 service installs, 4720 account creation, 4776 credential validation), "
                    "Prefetch content (strings on individual .pf files for loaded DLLs "
                    "and last-run timestamps), "
                    "Full SAM/SECURITY hive (rip.pl -r SAM -f samparse for account details; "
                    "rip.pl -r SECURITY -f lsa for LSA secrets / cached domain credentials), "
                    "Registry autorun beyond Run key (Winlogon Userinit/Shell, AppInit_DLLs, "
                    "Image File Execution Options, Browser Helper Objects, Scheduled Tasks XML), "
                    "Shellbags / LNK / MRU (rip.pl -r NTUSER.DAT -f shellbags, recentdocs, "
                    "userassist — reveals attacker navigation), "
                    "Hash + string + stat on every suspicious binary from Pass 1, "
                    "WER ReportQueue for crash dumps of attacker tools, "
                    "Network artifacts (hosts file, proxy config in registry, DNS cache in hives)"
                )

                messages: list[dict] = [{
                    'role': 'user',
                    'content': (
                        f"Windows image at {target_path}. Full forensic investigation.\n\n"
                        f"PASS 1 ALREADY CHECKED (do not repeat): {already_checked}\n\n"
                        f"Raw artifacts and strings collected during initial scan:\n"
                        f"{collected}\n\n"
                        f"AREAS NOT YET INVESTIGATED — work through these systematically:\n"
                        f"{uncovered}\n\n"
                        f"Budget: {MAX_AGENT_TOOLS} tool calls. For every suspicious file "
                        f"found: collect md5sum + stat + strings + prefetch before moving on. "
                        f"Build the evidence record as you go. Final assessment must cite "
                        f"exact paths, hashes, and timestamps for each confirmed technique. "
                        f"Do NOT speculate — every finding must be grounded in a directly "
                        f"observed artifact from a tool call."
                    ),
                }]

                tool_call_count  = 0
                stop_early       = False
                continuation_count = 0

                while not stop_early:
                    try:
                        response = client.messages.create(
                            model=os.environ.get('ADVERSA_MODEL', 'claude-sonnet-4-6'),
                            max_tokens=4096,
                            system=_AGENT_SYSTEM,
                            messages=messages,
                            tools=tools,
                        )
                    except Exception as api_err:
                        print(f"\n  ⚠️  Agentic pass unavailable: {api_err}")
                        analysis_text = "[Agentic pass unavailable — deterministic result only]"
                        break

                    if response.stop_reason == 'tool_use':
                        messages.append({'role': 'assistant',
                                         'content': response.content})
                        tool_results = []

                        for block in response.content:
                            if block.type != 'tool_use':
                                continue

                            tool_call_count += 1
                            tag = f"[A{tool_call_count}]"

                            if tool_call_count > MAX_AGENT_TOOLS:
                                output = "BUDGET_EXCEEDED: maximum tool calls reached"
                                print(f"  {tag} BUDGET EXCEEDED — halting")
                            else:
                                cmd_display = (
                                    block.input.get('command')
                                    or block.input.get('plugin')
                                    or str(block.input)
                                )[:100]
                                print(f"  {tag} {cmd_display}")
                                try:
                                    res = await session.call_tool(
                                        block.name, block.input
                                    )
                                    output = res.content[0].text
                                except Exception as exc:
                                    output = f"ERROR: {exc}"

                                cmd = block.input.get(
                                    'command', block.input.get('mount_path', ''))
                                _audit(block.name, cmd, output,
                                       getattr(response, 'usage', None))
                                tool_outputs.append(output)

                                # Store full output in tool log for the HTML report
                                pass2_tool_log.append({
                                    'call_num': tool_call_count,
                                    'cmd':      cmd_display,
                                    'output':   output[:3000],
                                })

                            tool_results.append({
                                'type':        'tool_result',
                                'tool_use_id': block.id,
                                'content':     output,
                            })

                        messages.append({'role': 'user', 'content': tool_results})

                        # Checkpoint: pause for operator at CHECKPOINT_AT calls
                        if tool_call_count == CHECKPOINT_AT:
                            stop_early = _checkpoint(
                                tool_call_count, pass1_hits, tool_outputs, rules
                            )

                        if tool_call_count >= MAX_AGENT_TOOLS or stop_early:
                            prompt = (
                                'Tool budget exhausted. Provide your final forensic '
                                'assessment: for each confirmed technique, state every '
                                'artifact with its exact path, MD5 hash, MAC timestamps, '
                                'and execution evidence. Plain prose only.'
                                if tool_call_count >= MAX_AGENT_TOOLS else
                                'Operator requested early report. Summarise all evidence '
                                'collected so far. For each technique, cite exact artifacts '
                                'with paths, hashes, and timestamps. Plain prose only.'
                            )
                            messages.append({'role': 'user', 'content': prompt})
                            try:
                                final_resp = client.messages.create(
                                    model=os.environ.get('ADVERSA_MODEL', 'claude-sonnet-4-6'),
                                    max_tokens=2048,
                                    system=_AGENT_SYSTEM,
                                    messages=messages,
                                )
                                analysis_text = '\n'.join(
                                    b.text for b in final_resp.content
                                    if hasattr(b, 'text')
                                )
                            except Exception:
                                analysis_text = (
                                    f"[{'Budget exhausted' if not stop_early else 'Early report'} "
                                    f"— {tool_call_count} tool calls completed]"
                                )
                            break

                    else:
                        partial_text = '\n'.join(
                            b.text for b in response.content if hasattr(b, 'text')
                        )
                        # If budget substantially unused, force continuation
                        if tool_call_count < 40 and continuation_count < 3:
                            continuation_count += 1
                            remaining = MAX_AGENT_TOOLS - tool_call_count
                            print(f"\n  ⟳ Agent concluded early "
                                  f"({tool_call_count} calls used, "
                                  f"{remaining} remaining) — injecting continuation "
                                  f"[{continuation_count}/3]")
                            messages.append({'role': 'assistant',
                                             'content': response.content})
                            messages.append({'role': 'user', 'content': (
                                f"You have {remaining} tool calls remaining. "
                                f"Do not stop investigating — the following domains "
                                f"have not yet been covered:\n"
                                f"• Event log content (.evtx): use EvtxECmd — "
                                f"dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll "
                                f"-f '<evtx_path>' --csv /tmp/evtx_out --csvf evtx.csv 2>/dev/null "
                                f"then grep -iE '7045|4624|4625|4688|4720' /tmp/evtx_out/evtx.csv | head -40 "
                                f"(do NOT use evtxexport — not in allowlist)\n"
                                f"• Prefetch binary parsing: strings on individual .pf "
                                f"files for last-run timestamps of every suspicious exe\n"
                                f"• SAM/SECURITY hive: rip.pl -r SAM -f samparse; "
                                f"rip.pl -r SECURITY -f lsa (LSA secrets / cached creds)\n"
                                f"• Hash + stat + strings on every suspicious binary "
                                f"not yet processed\n"
                                f"• WER ReportQueue crash dumps of attacker tools\n"
                                f"• Network artifacts: hosts file, proxy config in "
                                f"registry, WLAN profiles\n"
                                f"Continue with tool calls. Do not write a summary yet."
                            )})
                        else:
                            analysis_text = partial_text
                            break

                elapsed2 = (datetime.now(timezone.utc) - t2).total_seconds()
                final_score, final_hits, final_reasons = parse_findings(
                    tool_outputs, rules
                )

                # ── Pass 2 technique extraction ───────────────────────────
                # LLM prose analysis often surfaces techniques the signal
                # scorer missed (T1136, T1059, T1560, etc.). Extract them and
                # merge so the Auditor challenges everything Pass 2 found.
                if analysis_text.strip():
                    p2_extra = _extract_pass2_techniques(client, analysis_text)
                    for tid, sigs in p2_extra.items():
                        if tid not in final_hits:
                            patterns = rules if rules else BASE_PATTERNS
                            tname = patterns.get(tid, {}).get('name', tid)
                            final_hits[tid] = sigs
                            final_reasons.append(
                                f"{tname} (+0) [pass2-LLM] via: {sigs}"
                            )
                            print(f"  [P2+] {tid} ({tname}): {sigs}")

                delta     = final_score - pass1_score
                new_techs = sorted(set(final_hits.keys()) - set(pass1_hits.keys()))

                print(f"\n  Agentic pass: {tool_call_count} tool calls, "
                      f"{elapsed2:.1f}s, score={final_score} (Δ{delta:+d})")
                if new_techs:
                    print(f"  New detections: {', '.join(new_techs)}")

                pass_info.update({
                    'pass2_ran':        True,
                    'pass2_type':       'agentic',
                    'pass2_tool_calls': tool_call_count,
                    'pass2_score':      final_score,
                    'delta':            delta,
                    'new_techniques':   new_techs,
                    'early_stop':       stop_early,
                })

                if analysis_text:
                    print('\n=== ANALYSIS ===')
                    print(analysis_text)

            # ── Final verdict ─────────────────────────────────────────────
            print('\n=== CONFIDENCE SCORE ===')
            print(f'Compromise Confidence: {final_score}')
            for r in final_reasons:
                print(f'  • {r}')

            _HIGH_VALUE = {'T1003.001', 'T1071.001', 'T1569.002', 'T1547.001'}
            confirmed_high_value = any(t in _HIGH_VALUE for t in final_hits)
            if final_score >= 70 or confirmed_high_value:
                level = 'HIGH'
                if confirmed_high_value and final_score < 70:
                    print('\n🔴 HIGH CONFIDENCE — Confirmed high-value technique '
                          f'({", ".join(t for t in final_hits if t in _HIGH_VALUE)})')
                else:
                    print('\n🔴 HIGH CONFIDENCE — Likely Active Compromise')
            elif final_score >= 40:
                level = 'MEDIUM'
                print('\n🟡 MEDIUM CONFIDENCE — Suspicious Activity')
            else:
                level = 'LOW'
                print('\n🟢 LOW CONFIDENCE — No Strong IOCs')

            save_audit_log()
            save_findings_report(target_path, final_score, level, final_hits,
                                 final_reasons, tool_outputs, analysis_text,
                                 rules, pass_info, pass2_tool_log)

    return final_score, final_hits


async def main():
    parser = argparse.ArgumentParser(description='ASL-trained forensic triage agent')
    parser.add_argument('target', nargs='?', default='/mnt/nromanoff',
                        help='Mounted image path (e.g. /mnt/nfury)')
    parser.add_argument('--no-synthesis', action='store_true',
                        help='Skip Claude LLM synthesis — Pass 1 only')
    parser.add_argument('--ioc-file', metavar='PATH',
                        help='JSON file of case-specific IOCs')
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"ERROR: {args.target} not found or not mounted")
        sys.exit(1)

    ioc_data = None
    if args.ioc_file:
        if not os.path.exists(args.ioc_file):
            print(f"ERROR: IOC file not found: {args.ioc_file}")
            sys.exit(1)
        with open(args.ioc_file) as f:
            ioc_data = json.load(f)
        print(f"  IOC file: {args.ioc_file} "
              f"({sum(len(v) for v in ioc_data.values() if isinstance(v, list))} IOCs)")

    os.environ['BLUE_TARGET'] = args.target
    rules = load_operational_rules()
    await investigate(args.target, rules,
                      no_synthesis=args.no_synthesis, ioc_data=ioc_data)


if __name__ == '__main__':
    asyncio.run(main())
