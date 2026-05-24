"""
sift_server.py — SIFT MCP Server

Single-tool architecture: run_terminal_command + utility helpers.
Claude constructs SIFT CLI commands directly — no pre-packaged wrappers
that abstract away what the agent is actually doing.

Security model:
  - Explicit binary allowlist (every SIFT tool the agent legitimately needs)
  - /dev/null whitelisted as redirection target (output discard, not evidence)
  - Hard-blocked strings: destructive, exfil, privilege-escalation, injection
  - Atomic JSONL audit log (chain of custody)
"""

import json
import logging
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

logging.getLogger('mcp').setLevel(logging.WARNING)

mcp = FastMCP("SIFT Forensic Server")

_REPORTS = os.path.realpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
)
_AUDIT_LOG = os.path.join(_REPORTS, 'audit_log.jsonl')

# ── Comprehensive SIFT binary allowlist ──────────────────────────────────────
_ALLOWED_BINARIES = frozenset({
    # ── Volatility 3 ──
    'vol.py', 'vol',   # vol = /opt/volatility3/bin/vol on SIFT
    # ── Sleuth Kit ──
    'fls', 'icat', 'ils', 'mmls', 'fsstat', 'blkls', 'mactime',
    'tsk_recover', 'img_stat', 'srch_strings', 'tsk_comparedir', 'sigfind',
    # ── Registry tools ──
    'rip.pl', 'regripper',
    # ── EZ Tools (.NET) ──
    'dotnet',
    # ── YARA ──
    'yara',
    # ── EWF / image tools ──
    'ewfmount', 'ewfinfo', 'ewfverify',
    # ── Plaso ──
    'log2timeline.py', 'psort.py', 'pinfo.py',
    # ── bulk_extractor ──
    'bulk_extractor',
    # ── Python (for vol.py, scripts) ──
    'python3', 'python',
    # ── String / binary inspection ──
    'strings', 'xxd', 'hexdump', 'od', 'readelf', 'objdump',
    # ── Hashing ──
    'md5sum', 'sha1sum', 'sha256sum', 'ssdeep',
    # ── File identification ──
    'file', 'exiftool',
    # ── PDF / document ──
    'pdftotext', 'pdfinfo',
    # ── Text processing ──
    # sed removed: GNU sed's 'e' flag executes arbitrary shell commands,
    # bypassing all pipeline validation. Use awk or grep instead.
    'grep', 'find', 'cat', 'head', 'tail', 'sort', 'uniq', 'wc',
    'awk', 'cut', 'tr', 'paste', 'split', 'comm', 'diff', 'join',
    # ── System / path utilities ──
    'stat', 'ls', 'echo', 'printf', 'date', 'basename', 'dirname',
    # ── Encoding ──
    'iconv', 'base64',
    # ── JSON ──
    'jq',
    # ── Piping helpers ──
    'xargs', 'tee',
    # ── Misc forensic utils ──
    'foremost', 'photorec',
})

# ── Hard-blocked strings ─────────────────────────────────────────────────────
_HARD_BLOCKED = (
    # Destructive
    'shred', 'mkfs', 'fdisk', 'parted', 'wipefs',
    'dd if=/dev/zero', 'dd if=/dev/urandom',
    # Exfiltration
    'wget', 'curl ', 'nc ', 'ncat ', 'netcat ',
    'ssh ', 'scp ', 'rsync ',
    # Privilege escalation
    'sudo ', 'su ', 'pkexec',
    # Process / service manipulation
    'kill ', 'killall', 'systemctl', 'service ',
    # Command injection via substitution
    '$(', '`',
    # Variable expansion — ${VAR} can exfiltrate env secrets (e.g. ANTHROPIC_API_KEY)
    '${',
    # In-process shell execution via awk/gawk system() and similar builtins
    'system(',
)

_REDIR_RE  = re.compile(r'>>\s*(\S+)|(?<![>])>\s*(\S+)')

# xargs flags that consume the next token as a value (not the command)
_XARGS_ARG_FLAGS = frozenset({
    '-I', '-n', '-P', '-s', '-L', '-d', '-E', '-a',
    '--max-args', '--max-procs', '--max-lines',
    '--delimiter', '--eof', '--replace', '--arg-file',
})


def _check_write_target(raw: str) -> tuple[bool, str]:
    """
    Validate that a file write target (redirect or tee) resolves inside reports/.
    Uses os.getcwd() so the check matches what the shell will actually do —
    fixing the previous bug where relative paths were joined to _REPORTS instead
    of cwd, allowing 'reports/audit_log.jsonl' to pass incorrectly.
    """
    if raw == '/dev/null':
        return True, ''
    resolved = os.path.realpath(
        raw if os.path.isabs(raw) else os.path.join(os.getcwd(), raw)
    )
    # Explicit deny: audit log must never be writable through tool commands
    if os.path.basename(resolved) == 'audit_log.jsonl':
        return False, f"write to audit_log.jsonl is blocked"
    if not (resolved == _REPORTS or resolved.startswith(_REPORTS + os.sep)):
        return False, (
            f"write target {raw!r} resolves outside reports/ "
            f"(resolved: {resolved})"
        )
    return True, ''


def _split_pipeline(cmd: str) -> list[str]:
    """Split a shell command on | separators, skipping | inside single quotes."""
    segments: list[str] = []
    buf: list[str] = []
    in_sq = False
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if ch == "'":
            in_sq = not in_sq
            buf.append(ch)
        elif ch == '|' and not in_sq:
            if i + 1 < len(cmd) and cmd[i + 1] == '|':
                buf.append(ch)
                buf.append(cmd[i + 1])
                i += 2
                continue
            segments.append(''.join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append(''.join(buf))
    return segments


def _validate_command(command: str):
    """
    Multi-layer validation. Returns (allowed: bool, reason: str).

    Layer 1 — hard-blocked substrings (raw string, before any parsing)
    Layer 2 — per-pipeline-segment leading binary allowlist
              + per-binary argument guards:
                python3/python: -c blocked
                find:           -exec/-execdir target must be in allowlist
                xargs:          command argument must be in allowlist
                tee:            file targets validated same as redirect guard
    Layer 3 — all write targets (> >> and tee) resolved with os.getcwd()
              and must land inside reports/; audit_log.jsonl explicitly denied
    """
    cmd_lower = command.lower()
    for token in _HARD_BLOCKED:
        if token in cmd_lower:
            return False, f"hard-blocked token: {token!r}"

    for segment in _split_pipeline(command):
        clean = _REDIR_RE.sub('', segment).strip()
        if not clean:
            continue
        try:
            tokens = shlex.split(clean)
        except ValueError:
            tokens = clean.split()
        if not tokens:
            continue

        binary = os.path.basename(tokens[0]).lower()
        if binary not in _ALLOWED_BINARIES:
            return False, f"binary {binary!r} not in forensic allowlist"

        # ── python3 / python: block inline execution ──────────────────────
        if binary in ('python3', 'python') and len(tokens) > 1:
            if tokens[1].strip().lower() == '-c':
                return False, "python3 -c (inline code execution) is blocked"

        # ── find: validate -exec / -execdir target binary ─────────────────
        if binary == 'find':
            for i, tok in enumerate(tokens):
                if tok in ('-exec', '-execdir') and i + 1 < len(tokens):
                    exec_bin = os.path.basename(tokens[i + 1]).lower()
                    if exec_bin not in _ALLOWED_BINARIES:
                        return False, (
                            f"find {tok} binary {exec_bin!r} "
                            f"not in forensic allowlist"
                        )

        # ── xargs: validate the command argument ──────────────────────────
        if binary == 'xargs':
            i = 1
            while i < len(tokens):
                tok = tokens[i]
                if tok in _XARGS_ARG_FLAGS:
                    i += 2  # flag + its value
                    continue
                if tok.startswith('-'):
                    i += 1
                    continue
                # First non-flag token is the command xargs will run
                xargs_bin = os.path.basename(tok).lower()
                if xargs_bin not in _ALLOWED_BINARIES:
                    return False, (
                        f"xargs command {xargs_bin!r} "
                        f"not in forensic allowlist"
                    )
                break

        # ── tee: validate output file targets ─────────────────────────────
        if binary == 'tee':
            for tok in tokens[1:]:
                if not tok.startswith('-'):
                    ok, reason = _check_write_target(tok)
                    if not ok:
                        return False, f"tee target: {reason}"

    # ── Layer 3: shell redirect targets ───────────────────────────────────
    for match in _REDIR_RE.finditer(command):
        raw = match.group(1) or match.group(2)
        if not raw:
            continue
        ok, reason = _check_write_target(raw)
        if not ok:
            return False, f"redirection: {reason}"

    return True, ""


def _append_audit(entry: dict) -> None:
    os.makedirs(_REPORTS, exist_ok=True)
    line = (json.dumps(entry) + '\n').encode()
    fd = os.open(_AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def _run(cmd: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return r.stdout.strip() if r.returncode == 0 else r.stderr.strip()
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s"


# ── Path helpers — exported for blue_agent.py ────────────────────────────────

def windows_dir(mount_path: str) -> str:
    """Locate the Windows directory, handling XP uppercase WINDOWS."""
    for candidate in ('Windows', 'WINDOWS', 'windows'):
        p = os.path.join(mount_path, candidate)
        if os.path.isdir(p):
            return p
    return os.path.join(mount_path, 'Windows')


def system32_dir(mount_path: str) -> str:
    """Locate System32, handling XP lowercase system32."""
    win = windows_dir(mount_path)
    for candidate in ('System32', 'system32', 'SYSTEM32'):
        p = os.path.join(win, candidate)
        if os.path.isdir(p):
            return p
    return os.path.join(win, 'System32')


def config_dir(mount_path: str) -> str:
    return os.path.join(system32_dir(mount_path), 'config')


def profiles_dir(mount_path: str) -> str:
    """Locate user profiles root (Users on Win7, Documents and Settings on XP)."""
    for candidate in ('Users', 'Documents and Settings', 'DOCUMENTS AND SETTINGS'):
        p = os.path.join(mount_path, candidate)
        if os.path.isdir(p):
            return p
    return os.path.join(mount_path, 'Users')


def config_hive(mount_path: str, hive_name: str) -> str:
    """Return actual path to a registry hive, case-corrected."""
    cfg = config_dir(mount_path)
    exact = os.path.join(cfg, hive_name)
    if os.path.exists(exact):
        return exact
    if os.path.isdir(cfg):
        try:
            for entry in os.listdir(cfg):
                if entry.upper() == hive_name.upper():
                    return os.path.join(cfg, entry)
        except OSError:
            pass
    return exact


# ── Primary tool ─────────────────────────────────────────────────────────────

@mcp.tool()
def run_terminal_command(command: str) -> str:
    """
    Execute any native SIFT forensic utility with full CLI access.

    The agent constructs commands exactly as a human analyst would at the
    terminal — strings, grep, find, fls, rip.pl, vol.py, yara, etc.
    All SIFT-installed tools are available.

    Security constraints:
      - Binary allowlist: only forensic/analysis tools (no curl, wget, ssh, …)
      - Redirection restricted to reports/ or /dev/null
      - Hard-blocked: destructive ops, exfil, privilege escalation, injection
      - Every call is atomically appended to the chain-of-custody audit log

    Example commands:
      find /mnt/nfury -iname 'mimikatz.exe' 2>/dev/null
      strings /mnt/nfury/Windows/System32/spinlock.exe 2>/dev/null | head -60
      rip.pl -r /mnt/nfury/Windows/System32/config/SOFTWARE -f run 2>/dev/null
      /opt/volatility3/bin/vol -q -f /cases/mem.raw windows.pslist
      yara /path/to/rules.yar /mnt/nfury 2>/dev/null
      fls -r /dev/sdb1 | grep -i psexec
    """
    start = datetime.now(timezone.utc)

    allowed, reason = _validate_command(command)
    if not allowed:
        output = f"ERROR: Command blocked — {reason}"
        _append_audit({
            'timestamp':      start.isoformat(),
            'duration_ms':    0,
            'command':        command,
            'returncode':     -1,
            'blocked_reason': reason,
            'output_preview': output[:200],
        })
        return output

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        output    = result.stdout if result.returncode == 0 else f"STDERR: {result.stderr}"
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        output    = f"ERROR: Command timed out after 60s — {command[:80]!r}"
        returncode = -2

    end = datetime.now(timezone.utc)
    _append_audit({
        'timestamp':      start.isoformat(),
        'duration_ms':    int((end - start).total_seconds() * 1000),
        'command':        command,
        'returncode':     returncode,
        'output_length':  len(output),
        'output_preview': output[:300],
    })

    return output


# ── Utility tools ─────────────────────────────────────────────────────────────
# These complement run_terminal_command for structured lookups.

@mcp.tool()
def run_volatility(memory_image: str, plugin: str, extra_args: str = '') -> dict:
    """
    Run a Volatility 3 plugin against a memory image.

    Parameters:
      memory_image — absolute path to .raw/.mem/.lime/.vmem memory image
      plugin       — plugin name: windows.pslist, windows.netscan,
                     windows.malfind, windows.modules, windows.cmdline,
                     windows.dlllist, windows.handles, windows.filescan,
                     windows.registry.printkey, windows.pstree, etc.
      extra_args   — optional extra flags (e.g. '--pid 1234')
    """
    if not os.path.exists(memory_image):
        return {'error': f'Memory image not found: {memory_image}'}

    if not re.match(r'^[\w.]+$', plugin):
        return {'error': f'Invalid plugin name: {plugin!r}'}

    _vol = os.environ.get('VOL_PATH', '/opt/volatility3/bin/vol')
    cmd = f"{_vol} -q -f '{memory_image}' {plugin}"
    if extra_args:
        cmd += f' {extra_args}'

    allowed, reason = _validate_command(cmd)
    if not allowed:
        return {'error': f'Blocked: {reason}'}

    output = _run(cmd, timeout=120)
    lines  = [l for l in output.splitlines() if l.strip()]
    _append_audit({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'tool': 'run_volatility',
        'memory_image': memory_image,
        'plugin': plugin,
        'row_count': len(lines),
    })
    return {
        'memory_image': memory_image,
        'plugin':       plugin,
        'row_count':    len(lines),
        'output':       '\n'.join(lines[:60]),
        'truncated':    len(lines) > 60,
    }


@mcp.tool()
def search_ioc(mount_path: str, ioc: str, ioc_type: str = 'any') -> dict:
    """
    General-purpose IOC search: checks registry hives and filesystem.

    Parameters:
      mount_path — mounted image root (e.g. /mnt/nfury)
      ioc        — string to search (filename, IP, hash, keyword, username)
      ioc_type   — search strategy hint:
                   'filename'     → filesystem find -iname '*ioc*'
                   'ip'           → grep in registry hives
                   'registry_key' → strings on hives + NTUSER.DAT
                   'any'          → all of the above (default)
    """
    results = {'mount': mount_path, 'ioc': ioc, 'ioc_type': ioc_type,
               'hits': [], 'hit_count': 0}

    sw  = config_hive(mount_path, 'SOFTWARE')
    sys = config_hive(mount_path, 'SYSTEM')

    if ioc_type in ('ip', 'registry_key', 'any'):
        for hive in (sw, sys):
            if os.path.exists(hive):
                out = _run(f"strings '{hive}' 2>/dev/null | grep -i '{ioc}'")
                if out.strip():
                    results['hits'].append({
                        'location': f"registry:{os.path.basename(hive)}",
                        'context':  out.strip()[:300],
                    })

    if ioc_type in ('registry_key', 'any'):
        prof = profiles_dir(mount_path)
        nts  = _run(f"find '{prof}' -maxdepth 2 -name 'NTUSER.DAT' 2>/dev/null")
        for nt in nts.splitlines():
            nt = nt.strip()
            if nt and os.path.exists(nt):
                out = _run(f"strings '{nt}' 2>/dev/null | grep -i '{ioc}'")
                if out.strip():
                    results['hits'].append({
                        'location': f"registry:NTUSER({os.path.dirname(nt).split('/')[-1]})",
                        'context':  out.strip()[:300],
                    })

    if ioc_type in ('filename', 'any'):
        out = _run(f"find '{mount_path}' -iname '*{ioc}*' 2>/dev/null | head -10")
        for p in out.splitlines():
            p = p.strip()
            if p:
                results['hits'].append({'location': f"filesystem:{p}", 'context': ''})

    results['hit_count'] = len(results['hits'])
    _append_audit({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'tool': 'search_ioc',
        'mount_path': mount_path,
        'ioc': ioc,
        'hit_count': results['hit_count'],
    })
    return results


@mcp.tool()
def compute_file_hash(file_path: str, algorithm: str = 'md5') -> dict:
    """
    Compute md5 / sha1 / sha256 hash of a file for IOC verification.
    """
    if not os.path.exists(file_path):
        return {'error': f'File not found: {file_path}'}
    tool = {'md5': 'md5sum', 'sha1': 'sha1sum', 'sha256': 'sha256sum'}.get(algorithm, 'md5sum')
    out  = _run(f"{tool} '{file_path}' 2>/dev/null", timeout=30)
    hval = out.split()[0] if out.split() else ''
    _append_audit({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'tool': 'compute_file_hash',
        'file_path': file_path,
        'algorithm': algorithm,
        'hash': hval,
    })
    return {'file': file_path, 'algorithm': algorithm, 'hash': hval}


if __name__ == "__main__":
    mcp.run()
