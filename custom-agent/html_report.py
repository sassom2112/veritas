#!/usr/bin/env python3
"""
html_report.py -- Self-contained HTML report generator for VERITAS investigations.

Reads:  reports/{host}-auditor-transcript.json
        reports/{host}-custom-agent-report.json
        reports/{host}-investigation.json
Writes: reports/{host}-report.html
"""

import json
import os
import re
from datetime import datetime, timezone
import markdown as _md

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))


def _load(path: str) -> dict:
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    return {}


def _esc(s: str) -> str:
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _verdict_color(verdict: str) -> str:
    v = verdict.upper()
    if 'HIGH'   in v: return '#f85149'
    if 'MEDIUM' in v: return '#d29922'
    return '#3fb950'


def _verdict_icon(verdict: str) -> str:
    v = verdict.upper()
    if 'HIGH'   in v: return '⚠'
    if 'MEDIUM' in v: return '▲'
    return '✓'


def _raw_output_block(raw: str, label: str = 'Tool Output') -> str:
    if not raw or not raw.strip():
        return ''
    return f'''<details class="raw-output-details">
  <summary class="raw-output-summary">{_esc(label)}</summary>
  <pre class="raw-output">{_esc(raw.strip())}</pre>
</details>'''


def _round_html(r: dict) -> str:
    rv    = r.get('verdict', 'INCONCLUSIVE')
    color = '#3fb950' if rv == 'CONFIRMED' else '#f85149' if rv == 'REFUTED' else '#d29922'
    cmds  = r.get('tools_called', [])
    cmds_html = ''.join(
        f'<code class="round-cmd">{_esc(c)}</code>' for c in cmds
    ) if cmds else '<span class="round-tools">(no tools called)</span>'
    reasoning = _esc(r.get('reasoning', ''))
    raw_out   = r.get('tool_output', r.get('tool_output_preview', ''))
    raw_block = _raw_output_block(raw_out, f'Round {r["round"]} raw tool output')

    return f'''<div class="round">
  <div class="round-header">
    <span class="round-num">Round {r["round"]}</span>
    <div class="round-cmds">{cmds_html}</div>
    <span class="round-verdict" style="color:{color}">{rv}</span>
  </div>
  <div class="round-reasoning">{reasoning}</div>
  {raw_block}
</div>'''


def _finding_card(f: dict) -> str:
    verdict    = f.get('final_verdict', 'INCONCLUSIVE')
    confirmed  = verdict == 'CONFIRMED'
    tid        = _esc(f.get('finding_id', ''))
    name       = _esc(f.get('finding_name', ''))
    signals    = _esc(', '.join(f.get('triage_signals', [])))
    convergence = _esc(f.get('convergence_reason', '').replace('_', ' '))
    rounds     = f.get('challenges', [])
    total_cmds = sum(len(r.get('tools_called', [])) for r in rounds)

    is_inconclusive = verdict == 'INCONCLUSIVE'
    badge_cls  = ('confirmed-badge'    if confirmed else
                  'inconclusive-badge' if is_inconclusive else 'refuted-badge')
    card_cls   = ('confirmed-card'     if confirmed else
                  'inconclusive-card'  if is_inconclusive else 'refuted-card')
    badge_txt  = ('✓ CONFIRMED'        if confirmed else
                  '? INCONCLUSIVE'     if is_inconclusive else '✗ REFUTED')
    status_cls = 'finding-weight' if confirmed else 'finding-weight refuted-weight'
    status_txt = ('artifact verified'  if confirmed else
                  'not located'        if is_inconclusive else 'no artifact found')

    rounds_html = '\n'.join(_round_html(r) for r in rounds)
    tools_line  = (
        f'<div class="finding-tools">Auditor: '
        f'<span class="tool-list">{total_cmds} commands over '
        f'{len(rounds)} round(s)</span></div>'
        if total_cmds else ''
    )

    # Surface the confirming evidence (output from the CONFIRMED round) prominently
    confirming_evidence = ''
    if confirmed:
        for r in rounds:
            raw = r.get('tool_output', r.get('tool_output_preview', ''))
            if raw and raw.strip():
                confirming_evidence = f'''<div class="evidence-block">
  <div class="evidence-label">Confirming Evidence (raw tool output)</div>
  <pre class="evidence-pre">{_esc(raw.strip()[:2000])}</pre>
</div>'''
                break

    return f'''<div class="finding-card {card_cls}">
  <div class="finding-header">
    <div class="finding-id-block">
      <span class="finding-badge {badge_cls}">{badge_txt}</span>
      <span class="finding-tid">{tid}</span>
      <span class="finding-name">{name}</span>
    </div>
    <span class="{status_cls}">{status_txt}</span>
  </div>
  <div class="finding-signals">Triage signals: <span class="signal-list">{signals}</span></div>
  {tools_line}
  {confirming_evidence}
  <details class="finding-rounds">
    <summary>Auditor argumentation — {len(rounds)} round(s), {convergence}</summary>
    <div class="rounds-container">{rounds_html}</div>
  </details>
</div>'''


_CONTAINMENT = {
    'T1003.001': 'Assume all credentials on this host are compromised — rotate local admin, domain accounts, and any service accounts with logon activity in the attack window.',
    'T1071.001': 'Block C2 infrastructure at the perimeter firewall; review proxy/firewall logs for outbound connections to identified C2 IPs.',
    'T1059':     'Quarantine malicious executables in Temp directories; hunt the identified MD5 hash across the enterprise before containment.',
    'T1059.001': 'Review PowerShell script block logs and AppLocker/WDAC policy; hunt for encoded command patterns on adjacent hosts.',
    'T1189':     'Identify victim browsing vector (Java applet exploit); patch Java runtime; check proxy logs for the initial access IP.',
    'T1560':     'Assume data staging occurred — review FTP/SMB egress logs; identify what documents were in scope and notify data owner.',
    'T1136':     'Disable attacker-created account immediately; audit all actions taken under that account and any sessions it authenticated.',
    'T1547.001': 'Remove identified Run key persistence entries and verify no secondary persistence mechanisms remain.',
    'T1569.002': 'Verify PsExec was not used for lateral movement to adjacent hosts; check for PSEXESVC artifacts on other machines.',
}


def _executive_summary_html(confirmed: list, inconclusive: list, findings: list,
                             triage_rpt: dict) -> str:
    if not confirmed and not inconclusive:
        return ''

    # Attack narrative — first substantive paragraph of Pass 2 analysis
    analysis = triage_rpt.get('claude_analysis', '')
    narrative_html = ''
    if analysis:
        paras = [p.strip() for p in analysis.split('\n\n') if len(p.strip()) > 80]
        if paras:
            narrative_html = (
                f'<p class="exec-narrative">{_esc(paras[0][:700])}</p>'
            )

    # Collect C2 IPs and artifact hashes from confirmed findings
    c2_ips, tool_names = [], []
    for f in findings:
        if f.get('final_verdict') != 'CONFIRMED':
            continue
        for sig in f.get('triage_signals', []):
            if re.match(r'\d+\.\d+\.\d+\.\d+', sig) and sig not in c2_ips:
                c2_ips.append(sig)
            elif re.search(r'\.(exe|dll|dmp|ps1)$', sig, re.I) and sig not in tool_names:
                tool_names.append(sig)

    hashes: dict[str, str] = {}
    for entry in triage_rpt.get('pass2_tool_log', []):
        for line in entry.get('output', '').splitlines():
            m = re.match(r'([a-f0-9]{32})\s+(.+)', line.strip())
            if m:
                fname = os.path.basename(m.group(2).strip())
                hashes[fname] = m.group(1)

    # Containment actions
    actions = []
    for tid in confirmed:
        if tid in _CONTAINMENT:
            # splice in C2 IPs where relevant
            action = _CONTAINMENT[tid]
            if tid == 'T1071.001' and c2_ips:
                action = action.replace('identified C2 IPs',
                                        ', '.join(c2_ips))
            actions.append(action)

    actions_html = ''.join(
        f'<li class="action-item">{_esc(a)}</li>' for a in actions
    ) if actions else '<li class="action-item">Isolate host and preserve disk image for deeper analysis.</li>'

    # Technique chips
    def _chip(tid, verdict):
        color = 'var(--green)' if verdict == 'CONFIRMED' else 'var(--amber)'
        label = 'CONFIRMED' if verdict == 'CONFIRMED' else 'INCONCLUSIVE'
        return (f'<span class="exec-chip" style="border-color:{color};color:{color}">'
                f'{_esc(tid)} <span class="chip-verdict">{label}</span></span>')

    chips = ''.join(_chip(tid, 'CONFIRMED') for tid in confirmed)
    chips += ''.join(_chip(tid, 'INCONCLUSIVE') for tid in inconclusive)

    # IOC table
    ioc_rows = ''
    for ip in c2_ips:
        ioc_rows += f'<tr><td>C2 IP</td><td colspan="2"><code>{_esc(ip)}</code></td></tr>'
    for fname in tool_names:
        md5 = hashes.get(fname, '—')
        ioc_rows += (f'<tr><td>Malware</td><td>{_esc(fname)}</td>'
                     f'<td><code>{_esc(md5)}</code></td></tr>')
    for fname, md5 in hashes.items():
        if fname not in tool_names:
            ioc_rows += (f'<tr><td>Binary</td><td>{_esc(fname)}</td>'
                         f'<td><code>{_esc(md5)}</code></td></tr>')

    ioc_section = (
        f'<div class="exec-subtitle" style="margin-top:20px">IOCs for Enterprise Hunting</div>'
        f'<table class="ioc-table"><thead><tr>'
        f'<th>Type</th><th>Indicator</th><th>MD5</th>'
        f'</tr></thead><tbody>{ioc_rows}</tbody></table>'
    ) if ioc_rows else ''

    return f'''<section class="section exec-summary">
  <h2 class="section-title">Executive Summary</h2>
  {narrative_html}
  <div class="exec-techniques">{chips}</div>
  <div class="exec-grid">
    <div>
      <div class="exec-subtitle">Immediate Containment Actions</div>
      <ol class="action-list">{actions_html}</ol>
    </div>
  </div>
  {ioc_section}
</section>'''


def _pass2_log_html(tool_log: list) -> str:
    if not tool_log:
        return ''
    entries = []
    for entry in tool_log:
        n   = entry.get('call_num', '?')
        cmd = _esc(entry.get('cmd', ''))
        out = entry.get('output', '')
        raw_block = _raw_output_block(out, f'[A{n}] output') if out.strip() else ''
        entries.append(f'''<div class="log-entry">
  <div class="log-cmd"><span class="log-num">[A{n}]</span> {cmd}</div>
  {raw_block}
</div>''')
    entries_html = '\n'.join(entries)
    return f'''<section class="section">
  <h2 class="section-title">Pass 2 Investigation Log ({len(tool_log)} tool calls)</h2>
  <div class="log-container">{entries_html}</div>
</section>'''


_CSS = '''
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #0a0e17;
  --surface: #0d1117;
  --surf2:   #161b22;
  --border:  #21262d;
  --border2: #30363d;
  --text:    #e6edf3;
  --dim:     #7d8590;
  --green:   #3fb950;
  --red:     #f85149;
  --amber:   #d29922;
  --blue:    #58a6ff;
  --purple:  #bc8cff;
  --mono:    'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;
}

body {
  background: var(--bg); color: var(--text);
  font-family: var(--mono); font-size: 13px; line-height: 1.6;
}

.page-wrap { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }

/* ── Header ── */
.report-header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 28px; }
.report-title  { font-size: 11px; letter-spacing: .15em; text-transform: uppercase; color: var(--blue); margin-bottom: 6px; }
.report-host   { font-size: 22px; font-weight: 700; }
.report-meta   { margin-top: 8px; color: var(--dim); font-size: 12px; display: flex; gap: 24px; flex-wrap: wrap; }
.report-meta span::before { content: '⬡ '; color: var(--border2); }

/* ── Verdict banner ── */
.verdict-banner {
  border: 1px solid; border-radius: 6px; padding: 16px 20px; margin-bottom: 28px;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
}
.verdict-left  { display: flex; align-items: center; gap: 12px; }
.verdict-icon  { font-size: 24px; }
.verdict-text  { font-size: 15px; font-weight: 700; letter-spacing: .02em; }
.verdict-right { text-align: right; }
.score-pair    { font-size: 20px; font-weight: 700; }
.score-arrow   { color: var(--dim); margin: 0 8px; }
.score-label   { font-size: 11px; color: var(--dim); text-transform: uppercase; letter-spacing: .1em; }

/* ── Stats ── */
.stats-row { display: grid; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); gap: 12px; margin-bottom: 32px; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; }
.stat-value { font-size: 22px; font-weight: 700; }
.stat-label { font-size: 11px; color: var(--dim); text-transform: uppercase; letter-spacing: .08em; margin-top: 2px; }

/* ── Sections ── */
.section       { margin-bottom: 32px; }
.section-title {
  font-size: 11px; text-transform: uppercase; letter-spacing: .15em; color: var(--dim);
  padding-bottom: 8px; border-bottom: 1px solid var(--border); margin-bottom: 16px;
}

/* ── Finding cards ── */
.finding-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 16px; margin-bottom: 12px; border-left-width: 3px;
}
.confirmed-card { border-left-color: var(--green); }
.refuted-card   { border-left-color: var(--red);   }

.finding-header   { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }
.finding-id-block { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.finding-badge    { font-size: 10px; font-weight: 700; letter-spacing: .1em; padding: 2px 8px; border-radius: 3px; }
.confirmed-badge  { background: rgba(63,185,80,.15); color: var(--green); border: 1px solid rgba(63,185,80,.3); }
.refuted-badge    { background: rgba(248,81,73,.15);  color: var(--red);   border: 1px solid rgba(248,81,73,.3); }
.finding-tid      { font-weight: 700; color: var(--blue); }
.finding-name     { color: var(--dim); }
.finding-weight   { font-size: 13px; font-weight: 700; color: var(--green); white-space: nowrap; }
.refuted-weight   { color: var(--dim); text-decoration: line-through; }

.finding-signals, .finding-tools { font-size: 12px; color: var(--dim); margin-bottom: 4px; }
.signal-list, .tool-list { color: var(--purple); }

/* ── Confirming evidence block ── */
.evidence-block {
  background: rgba(63,185,80,.05); border: 1px solid rgba(63,185,80,.2);
  border-radius: 4px; padding: 12px 14px; margin: 12px 0;
}
.evidence-label {
  font-size: 10px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--green); margin-bottom: 8px;
}
.evidence-pre {
  font-family: var(--mono); font-size: 11px; color: var(--text);
  white-space: pre-wrap; word-break: break-all; line-height: 1.5;
  max-height: 320px; overflow-y: auto;
}

/* ── Raw output details ── */
.raw-output-details { margin-top: 8px; }
.raw-output-summary {
  cursor: pointer; font-size: 10px; color: var(--dim); letter-spacing: .08em;
  text-transform: uppercase; user-select: none; list-style: none; padding: 4px 0;
}
.raw-output-summary::before       { content: '▶  '; color: var(--border2); }
details[open] .raw-output-summary::before { content: '▼  '; }
.raw-output-summary:hover { color: var(--text); }
.raw-output {
  font-family: var(--mono); font-size: 11px; color: var(--dim);
  background: var(--surf2); border: 1px solid var(--border); border-radius: 4px;
  padding: 10px 12px; margin-top: 6px; white-space: pre-wrap; word-break: break-all;
  line-height: 1.5; max-height: 400px; overflow-y: auto;
}

/* ── Rounds ── */
.finding-rounds { margin-top: 12px; }
.finding-rounds > summary {
  cursor: pointer; font-size: 11px; color: var(--dim); text-transform: uppercase;
  letter-spacing: .08em; user-select: none; padding: 6px 0; list-style: none;
}
.finding-rounds > summary::before       { content: '▶  '; color: var(--border2); }
.finding-rounds[open] > summary::before { content: '▼  '; }
.finding-rounds > summary:hover { color: var(--text); }

.rounds-container { margin-top: 10px; display: flex; flex-direction: column; gap: 8px; }
.round {
  background: var(--surf2); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px;
}
.round-header {
  display: flex; align-items: center; gap: 12px; margin-bottom: 6px; flex-wrap: wrap;
}
.round-num     { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .1em; color: var(--dim); flex-shrink: 0; }
.round-tools   { font-size: 11px; color: var(--purple); }
.round-cmds    { display: flex; flex-direction: column; gap: 3px; flex: 1; min-width: 0; }
.round-cmd     { font-family: var(--mono); font-size: 11px; color: var(--green);
                 background: var(--bg); padding: 2px 6px; border-radius: 3px;
                 border: 1px solid var(--border); word-break: break-all;
                 white-space: pre-wrap; display: block; }
.round-verdict { font-size: 11px; font-weight: 700; margin-left: auto; flex-shrink: 0; }
.round-reasoning {
  font-size: 12px; color: var(--dim); line-height: 1.5;
  white-space: pre-wrap; word-break: break-word;
}

/* ── Executive summary ── */
.exec-summary    { background: var(--surface); border: 1px solid var(--border2);
                   border-radius: 6px; padding: 20px 24px; }
.exec-narrative  { font-size: 12px; color: var(--text); line-height: 1.7;
                   margin-bottom: 16px; white-space: pre-wrap; word-break: break-word; }
.exec-techniques { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }
.exec-chip       { font-size: 11px; font-weight: 700; padding: 3px 10px;
                   border-radius: 12px; border: 1px solid; letter-spacing: .05em; }
.chip-verdict    { font-weight: 400; opacity: .8; }
.exec-grid       { display: grid; gap: 20px; }
.exec-subtitle   { font-size: 10px; font-weight: 700; text-transform: uppercase;
                   letter-spacing: .12em; color: var(--dim); margin-bottom: 10px; }
.action-list     { padding-left: 20px; }
.action-item     { font-size: 12px; color: var(--text); line-height: 1.6;
                   margin-bottom: 6px; }
.ioc-table       { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
.ioc-table th    { text-align: left; font-size: 10px; text-transform: uppercase;
                   letter-spacing: .1em; color: var(--dim); padding: 4px 12px 4px 0;
                   border-bottom: 1px solid var(--border); }
.ioc-table td    { padding: 5px 12px 5px 0; border-bottom: 1px solid var(--border);
                   vertical-align: top; }
.ioc-table td:first-child { color: var(--dim); width: 80px; }
.ioc-table code  { font-family: var(--mono); color: var(--purple); }

/* ── Inconclusive finding cards ── */
.inconclusive-card   { border-left-color: var(--amber); }
.inconclusive-badge  { background: rgba(210,153,34,.15); color: var(--amber);
                       border: 1px solid rgba(210,153,34,.3); }

/* ── Pass 2 tool log ── */
.log-container { display: flex; flex-direction: column; gap: 6px; }
.log-entry {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 4px; padding: 8px 12px;
}
.log-cmd  { font-size: 12px; color: var(--text); margin-bottom: 4px; }
.log-num  { color: var(--purple); font-weight: 700; margin-right: 6px; }

/* ── Synthesis (LLM hypothesis) ── */
.synthesis-header {
  display: flex; align-items: center; gap: 10px; margin-bottom: 12px;
}
.synthesis-warning {
  font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase;
  color: var(--amber); background: rgba(210,153,34,.1);
  border: 1px solid rgba(210,153,34,.3); border-radius: 3px; padding: 2px 8px;
}
.synthesis-box {
  background: var(--surface); border: 1px solid rgba(210,153,34,.25); border-radius: 6px;
  padding: 20px 24px; overflow-x: auto;
}
.prose { font-family: var(--mono); font-size: 13px; color: var(--dim); line-height: 1.7; }
.prose h1, .prose h2, .prose h3 {
  color: var(--text); font-weight: 700; margin: 1.2em 0 0.4em;
}
.prose h1 { font-size: 17px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.prose h2 { font-size: 15px; }
.prose h3 { font-size: 13px; color: var(--blue); }
.prose p  { margin: 0.6em 0; }
.prose strong { color: var(--text); font-weight: 700; }
.prose em     { color: var(--amber); font-style: normal; }
.prose hr     { border: none; border-top: 1px solid var(--border); margin: 1em 0; }
.prose ul, .prose ol { padding-left: 1.5em; margin: 0.4em 0; }
.prose li     { margin: 0.2em 0; }
.prose code   { background: var(--surf2); padding: 1px 5px; border-radius: 3px;
                color: var(--purple); font-size: 12px; }
.prose pre    { background: var(--surf2); padding: 10px 12px; border-radius: 4px;
                overflow-x: auto; margin: 0.6em 0; }

/* ── Footer ── */
.report-footer {
  margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border);
  color: var(--dim); font-size: 11px; display: flex; justify-content: space-between;
}

::-webkit-scrollbar            { width: 6px; height: 6px; background: var(--bg); }
::-webkit-scrollbar-thumb      { background: var(--border2); border-radius: 3px; }
'''


def generate_report(host: str, reports_dir: str) -> str:
    transcript = _load(os.path.join(reports_dir, f'{host}-auditor-transcript.json'))
    triage_rpt = _load(os.path.join(reports_dir, f'{host}-custom-agent-report.json'))
    invest_rpt = _load(os.path.join(reports_dir, f'{host}-investigation.json'))

    target         = transcript.get('target', host)
    triage_score   = transcript.get('triage_score', 0)
    adjusted_score = min(transcript.get('adjusted_score', 0), 100)
    confirmed      = transcript.get('confirmed_findings', [])
    inconclusive   = transcript.get('inconclusive_findings', [])
    refuted        = transcript.get('refuted_findings', [])
    findings       = transcript.get('transcript', [])
    verdict        = invest_rpt.get('final_verdict', 'LOW — No confirmed compromise indicators')
    elapsed        = invest_rpt.get('elapsed_s', 0)
    generated      = transcript.get('generated', datetime.now(timezone.utc).isoformat())
    total_rounds   = sum(len(f.get('challenges', [])) for f in findings)
    pass_info      = triage_rpt.get('two_pass_scan', {}) or {}
    pass2_calls    = pass_info.get('pass2_tool_calls', 0)
    pass2_tool_log = triage_rpt.get('pass2_tool_log', [])

    vc = _verdict_color(verdict)
    vi = _verdict_icon(verdict)

    try:
        dt = datetime.fromisoformat(generated.replace('Z', '+00:00'))
        ts = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        ts = generated

    confirmed_cards     = '\n'.join(
        _finding_card(f) for f in findings if f.get('final_verdict') == 'CONFIRMED'
    )
    inconclusive_cards  = '\n'.join(
        _finding_card(f) for f in findings if f.get('final_verdict') == 'INCONCLUSIVE'
    )
    refuted_cards = '\n'.join(
        _finding_card(f) for f in findings if f.get('final_verdict') == 'REFUTED'
    )

    # Synthesis — labeled as LLM hypothesis, not independently verified
    synthesis_html = ''
    synthesis = triage_rpt.get('claude_analysis', '')
    if synthesis:
        rendered = _md.markdown(
            synthesis[:6000],
            extensions=['tables', 'fenced_code'],
        )
        synthesis_html = f'''<section class="section">
  <div class="synthesis-header">
    <h2 class="section-title" style="margin-bottom:0;border:none;padding:0">
      Triage Synthesis (Pass 2 LLM Assessment)
    </h2>
    <span class="synthesis-warning">⚠ LLM hypothesis — verify against raw evidence above</span>
  </div>
  <div class="synthesis-box prose">{rendered}</div>
</section>'''

    exec_summary = _executive_summary_html(
        confirmed, inconclusive, findings, triage_rpt
    )

    confirmed_section = f'''<section class="section">
  <h2 class="section-title">Confirmed Techniques ({len(confirmed)})</h2>
  {confirmed_cards}
</section>''' if confirmed else ''

    inconclusive_section = f'''<section class="section">
  <h2 class="section-title">Inconclusive — Artifact Not Located on Disk ({len(inconclusive)})</h2>
  <p style="font-size:12px;color:var(--dim);margin-bottom:12px">
    Triage signalled these techniques but the Auditor could not independently locate
    the physical artifact. Evidence may reside in unreadable formats, memory only,
    or network logs not present on this image. Manual follow-up required.
  </p>
  {inconclusive_cards}
</section>''' if inconclusive else ''

    refuted_section = f'''<section class="section">
  <h2 class="section-title">Refuted — False Positives Caught ({len(refuted)})</h2>
  {refuted_cards}
</section>''' if refuted else ''

    pass2_log_section = _pass2_log_html(pass2_tool_log)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>VERITAS — {_esc(host)}</title>
  <style>{_CSS}</style>
</head>
<body>
<div class="page-wrap">

  <header class="report-header">
    <div class="report-title">VERITAS · Forensic Investigation Report</div>
    <div class="report-host">{_esc(str(target))}</div>
    <div class="report-meta">
      <span>{_esc(ts)}</span>
      <span>Elapsed: {elapsed:.0f}s</span>
      <span>Pass 2: {pass2_calls} tool calls</span>
      <span>Triage Agent → Forensic Auditor</span>
    </div>
  </header>

  <div class="verdict-banner" style="border-color:{vc}44;background:{vc}0d;">
    <div class="verdict-left">
      <span class="verdict-icon" style="color:{vc}">{vi}</span>
      <span class="verdict-text" style="color:{vc}">{_esc(verdict)}</span>
    </div>
    <div class="verdict-right">
      <div class="score-pair">
        <span style="color:#3fb950">{len(confirmed)} confirmed</span>
        <span class="score-arrow">·</span>
        <span style="color:#f85149">{len(refuted)} refuted</span>
      </div>
      <div class="score-label">Auditor Verdicts</div>
    </div>
  </div>

  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-value" style="color:var(--green)">{len(confirmed)}</div>
      <div class="stat-label">Confirmed Techniques</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:var(--amber)">{len(inconclusive)}</div>
      <div class="stat-label">Inconclusive</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:var(--red)">{len(refuted)}</div>
      <div class="stat-label">False Positives Caught</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:var(--blue)">{total_rounds}</div>
      <div class="stat-label">Auditor Rounds</div>
    </div>
  </div>

  {exec_summary}
  {confirmed_section}
  {inconclusive_section}
  {refuted_section}
  {synthesis_html}
  {pass2_log_section}

  <footer class="report-footer">
    <span>VERITAS — Forensic Investigation Report</span>
    <span>Generated: {_esc(ts)}</span>
  </footer>

</div>
</body>
</html>'''

    out_path = os.path.join(reports_dir, f'{host}-report.html')
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    return out_path


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Generate HTML investigation report')
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument('--host',       help='Host name (e.g. nfury, controller)')
    grp.add_argument('--transcript', help='Path to auditor transcript JSON')
    args = parser.parse_args()

    host = args.host
    if args.transcript:
        base = os.path.basename(args.transcript)
        host = base.replace('-auditor-transcript.json', '')

    path = generate_report(host, _REPORTS)
    print(f'HTML report: {path}')
