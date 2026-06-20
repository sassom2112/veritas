"""
msticpy_enrichment.py

Enrichment layer for Mordor Sysmon events before they reach the Blue Agent.
When MSTICPy is installed (`pip install msticpy`), real enrichment activates.
Without it, built-in enrichment runs on stdlib only.

Provides:
  enrich_event(event_dict)      — adds context fields to a raw Sysmon event
  build_process_tree(events)    — reconstruct parent-child process chains
  classify_registry_key(path)   — ASEP categories, credential stores
  classify_network(ip, port)    — RFC1918, loopback, known C2 patterns
  MordorEnricher                — drop-in wrapper for MordorRedAgent

Usage in mordor_agent.py / brain.py:
    from msticpy_enrichment import MordorEnricher
    enricher = MordorEnricher(mordor_agent)
    technique_id, enriched_artifact = enricher.next_enriched()
"""
import re
import socket
import struct
from typing import Any

# ── MSTICPy probe ────────────────────────────────────────────────────────────
try:
    import msticpy                                    # type: ignore
    from msticpy.data.context.ip_utils import get_ip_type   # type: ignore
    _MSTICPY_AVAILABLE = True
    print(f"✅ MSTICPy {msticpy.__version__} detected — full enrichment active")
except ImportError:
    _MSTICPY_AVAILABLE = False

# ── Registry key classification ──────────────────────────────────────────────
# ASEP = AutoStart Extension Points (persistence mechanisms)
_REGISTRY_CATEGORIES = {
    'ASEP_RUN': [
        r'\\CurrentVersion\\Run\b',
        r'\\CurrentVersion\\RunOnce\b',
        r'\\CurrentVersion\\RunServices\b',
        r'\\Explorer\\Shell Folders',
        r'\\Explorer\\User Shell Folders',
        r'\\Winlogon\\Shell',
        r'\\Winlogon\\Userinit',
        r'\\Active Setup\\Installed Components',
    ],
    'CREDENTIAL_STORE': [
        r'\\Control\\Lsa\b',
        r'\\Control\\SecurityProviders',
        r'\\Control\\Lsa\\Notification',
        r'\\LSA\\',
        r'\\SAM\\',
        r'\\SECURITY\\',
        r'\\Secrets\\',
        r'\\Vault\\',
    ],
    'SERVICE_INSTALL': [
        r'\\System\\CurrentControlSet\\Services\\',
        r'\\Services\\PSEXESVC',
    ],
    'COM_HIJACK': [
        r'\\CLSID\\',
        r'\\InprocServer32',
        r'\\Classes\\CLSID',
    ],
    'NETWORK_CONFIG': [
        r'\\NetworkProvider\\Order',
        r'\\Tcpip\\Parameters',
        r'\\NetworkSetup2\\',
    ],
    'CERTIFICATE_STORE': [
        r'\\SystemCertificates\\',
        r'\\EnterpriseCertificates\\',
        r'\\Cryptography\\',
    ],
}

_REGISTRY_PATTERNS = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in _REGISTRY_CATEGORIES.items()
}


def classify_registry_key(path: str) -> dict[str, Any]:
    """
    Returns enrichment context for a Windows registry path.
    {'category': 'ASEP_RUN', 'high_value': True, 'description': '...'}
    """
    if not path:
        return {'category': 'UNKNOWN', 'high_value': False, 'description': ''}

    for category, compiled in _REGISTRY_PATTERNS.items():
        if any(rx.search(path) for rx in compiled):
            high_value = category in ('ASEP_RUN', 'CREDENTIAL_STORE', 'SERVICE_INSTALL')
            return {
                'category': category,
                'high_value': high_value,
                'description': _REGISTRY_CATEGORIES[category][0].replace('\\\\', '\\'),
            }

    return {'category': 'BENIGN_CONFIG', 'high_value': False, 'description': ''}


# ── Network classification ────────────────────────────────────────────────────
def _ip_to_int(ip: str) -> int:
    try:
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    except OSError:
        return 0


_RFC1918 = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
]
_LOOPBACK = (0x7F000000, 0xFF000000)  # 127.0.0.0/8
_LINK_LOCAL = (0xA9FE0000, 0xFFFF0000)  # 169.254.0.0/16

# Known malicious IPs from nromanoff investigation
_KNOWN_C2_IPS = {'12.190.135.235', '199.73.28.114'}

# Suspicious port categories
_PORT_CATEGORIES = {
    'C2_COMMON': {4444, 8080, 8443, 9001, 9002, 1080, 3128},
    'ADMIN': {22, 23, 3389, 5985, 5986, 135, 445, 139},
    'STANDARD_WEB': {80, 443, 8080, 8443},
}


def classify_network(ip: str, port: int = 0) -> dict[str, Any]:
    """
    Classify an IP+port combination for suspicious activity context.
    """
    if not ip:
        return {'type': 'UNKNOWN', 'suspicious': False, 'context': ''}

    # Known IOC
    if ip in _KNOWN_C2_IPS:
        return {
            'type': 'KNOWN_C2',
            'suspicious': True,
            'context': f'Confirmed C2 IP from nromanoff investigation',
            'ioc_match': True,
        }

    n = _ip_to_int(ip)
    if (n & _LOOPBACK[1]) == _LOOPBACK[0]:
        return {'type': 'LOOPBACK', 'suspicious': False, 'context': 'localhost'}
    if (n & _LINK_LOCAL[1]) == _LINK_LOCAL[0]:
        return {'type': 'LINK_LOCAL', 'suspicious': False, 'context': 'link-local'}
    for net, mask in _RFC1918:
        if (n & mask) == net:
            suspicious = port in _PORT_CATEGORIES.get('ADMIN', set())
            return {
                'type': 'RFC1918',
                'suspicious': suspicious,
                'context': f'Internal network{"  — admin port" if suspicious else ""}',
            }

    # Public IP
    port_cat = next(
        (cat for cat, ports in _PORT_CATEGORIES.items() if port in ports), 'OTHER'
    )
    suspicious = port_cat == 'C2_COMMON' or port not in (80, 443)
    return {
        'type': 'PUBLIC',
        'suspicious': suspicious,
        'context': f'Public IP  port={port}  category={port_cat}',
        'ioc_match': False,
    }


# ── Process relationship analysis ────────────────────────────────────────────
_SUSPICIOUS_PARENT_CHILD = [
    # Office apps spawning shells
    ('winword.exe', 'cmd.exe'),
    ('winword.exe', 'powershell.exe'),
    ('excel.exe', 'cmd.exe'),
    ('excel.exe', 'powershell.exe'),
    # Double-hop execution
    ('wscript.exe', 'powershell.exe'),
    ('cscript.exe', 'powershell.exe'),
    # WMI → shell
    ('wmiprvse.exe', 'cmd.exe'),
    ('wmiprvse.exe', 'powershell.exe'),
    # Masquerading: svchost in wrong location
    ('services.exe', 'psexesvc.exe'),
    # Credential dumping
    ('lsass.exe', 'mimikatz.exe'),
    ('cmd.exe', 'hydrakatz.exe'),
]


def classify_process_relationship(parent_image: str,
                                   child_image: str) -> dict[str, Any]:
    """Flag suspicious parent→child process chains."""
    if not parent_image or not child_image:
        return {'suspicious': False, 'context': ''}

    parent = os.path.basename(parent_image).lower() if '\\' in parent_image else parent_image.lower()
    child = os.path.basename(child_image).lower() if '\\' in child_image else child_image.lower()

    for sus_parent, sus_child in _SUSPICIOUS_PARENT_CHILD:
        if sus_parent in parent and sus_child in child:
            return {
                'suspicious': True,
                'context': f'Suspicious spawn: {sus_parent} → {sus_child}',
                'mitre_hint': 'T1059 / T1569',
            }

    return {'suspicious': False, 'context': f'{parent} → {child}'}


import os  # noqa: E402 — needed for basename above; keep at module level


# ── Event enrichment ─────────────────────────────────────────────────────────
def enrich_event(event: dict[str, Any]) -> dict[str, Any]:
    """
    Add enrichment fields to a raw Sysmon event dict.
    Non-destructive: returns a new dict with added 'enrichment' key.
    """
    enrichment: dict[str, Any] = {'msticpy_active': _MSTICPY_AVAILABLE}
    event_id = event.get('EventID', 0)

    # Registry enrichment (EventID 12/13/14)
    if event_id in (12, 13, 14):
        target_obj = event.get('TargetObject', '')
        reg_ctx = classify_registry_key(target_obj)
        enrichment['registry'] = reg_ctx
        if reg_ctx['high_value']:
            enrichment['alert_reason'] = f"High-value registry key modified: {reg_ctx['category']}"

    # Network enrichment (EventID 3)
    elif event_id == 3:
        dest_ip = event.get('DestinationIp', '')
        dest_port = int(event.get('DestinationPort', 0))
        net_ctx = classify_network(dest_ip, dest_port)
        enrichment['network'] = net_ctx
        if net_ctx.get('suspicious'):
            enrichment['alert_reason'] = net_ctx.get('context', 'Suspicious connection')

    # Process creation enrichment (EventID 1)
    elif event_id == 1:
        image = event.get('Image', '')
        parent = event.get('ParentImage', '')
        proc_ctx = classify_process_relationship(parent, image)
        enrichment['process_relationship'] = proc_ctx
        if proc_ctx['suspicious']:
            enrichment['alert_reason'] = proc_ctx['context']

    # Process access enrichment (EventID 10)
    elif event_id == 10:
        target = event.get('TargetImage', '')
        source = event.get('SourceImage', '')
        if 'lsass' in target.lower():
            enrichment['alert_reason'] = 'LSASS process access — possible credential dumping'
            enrichment['lsass_access'] = True
        proc_ctx = classify_process_relationship(source, target)
        enrichment['process_relationship'] = proc_ctx

    # MSTICPy-specific enrichment (only when installed)
    if _MSTICPY_AVAILABLE:
        dest_ip = event.get('DestinationIp', '')
        if dest_ip:
            try:
                enrichment['ip_type'] = get_ip_type(dest_ip)
            except Exception:
                pass

    return {**event, 'enrichment': enrichment}


def build_process_tree(events: list[dict]) -> dict[str, list[str]]:
    """
    Reconstruct parent→child process chains from a list of EventID=1 events.
    Returns {parent_pid: [child_pids]} mapping.
    """
    tree: dict[str, list[str]] = {}
    for ev in events:
        if ev.get('EventID') != 1:
            continue
        pid = str(ev.get('ProcessId', ''))
        ppid = str(ev.get('ParentProcessId', ''))
        if ppid:
            tree.setdefault(ppid, []).append(pid)
    return tree


# ── MordorEnricher wrapper ────────────────────────────────────────────────────
class MordorEnricher:
    """
    Drop-in wrapper for MordorRedAgent that adds enrichment context
    to each event before it reaches the Blue Agent scoring engine.

    Usage:
        from mordor_agent import MordorRedAgent
        from msticpy_enrichment import MordorEnricher
        agent = MordorRedAgent()
        enricher = MordorEnricher(agent)
        technique_id, artifact = enricher.next_enriched()
    """

    def __init__(self, mordor_agent):
        self.agent = mordor_agent
        self._enrichment_log: list[dict] = []

    def next_enriched(self, benign_ratio: float = 0.3) -> tuple[str, str]:
        """
        Return (technique_id, enriched_artifact_string).
        The artifact string has enrichment annotations appended.
        """
        technique_id, artifact = self.agent.next_technique(benign_ratio)

        # Parse the pipe-delimited artifact back into a pseudo-event
        pseudo_event = self._parse_artifact(artifact)
        enriched = enrich_event(pseudo_event)
        ctx = enriched.get('enrichment', {})

        # Append enrichment tokens to the artifact string for the Blue Agent
        extra_tokens = []
        if ctx.get('alert_reason'):
            extra_tokens.append(f"[ENRICH:{ctx['alert_reason'][:60]}]")
        if ctx.get('lsass_access'):
            extra_tokens.append('[LSASS_ACCESS]')
        reg = ctx.get('registry', {})
        if reg.get('high_value'):
            extra_tokens.append(f"[REG_CAT:{reg['category']}]")
        net = ctx.get('network', {})
        if net.get('ioc_match'):
            extra_tokens.append('[KNOWN_C2_IOC]')

        enriched_artifact = artifact
        if extra_tokens:
            enriched_artifact = artifact + ' ' + ' '.join(extra_tokens)

        self._enrichment_log.append({
            'technique': technique_id,
            'original': artifact[:80],
            'tokens_added': extra_tokens,
        })

        return technique_id, enriched_artifact

    # mordor_agent._format_event() uses short aliases; map to canonical Sysmon names
    _FIELD_ALIASES: dict[str, str] = {
        'Source': 'SourceImage',
        'Target': 'TargetImage',
        'Access': 'GrantedAccess',
        'Registry': 'TargetObject',
        'Value': 'Details',
        'Process': 'Image',
        'Parent': 'ParentImage',
        'DestIP': 'DestinationIp',
        'DestPort': 'DestinationPort',
        'File': 'TargetFilename',
        'Host': 'Hostname',
        'StartAddr': 'StartAddress',
        'CallTrace': 'CallTrace',
        'CommandLine': 'CommandLine',
        'User': 'AccountName',
        'Type': 'EventType',
    }

    @classmethod
    def _parse_artifact(cls, artifact: str) -> dict:
        """Convert a pipe-delimited artifact string into a pseudo-event dict."""
        event: dict[str, Any] = {}
        for segment in artifact.split('|'):
            segment = segment.strip()
            if '=' in segment:
                key, _, val = segment.partition('=')
                key = cls._FIELD_ALIASES.get(key.strip(), key.strip())
                val = val.strip()
                if key == 'EventID':
                    try:
                        event['EventID'] = int(val)
                    except ValueError:
                        pass
                else:
                    event[key] = val
            else:
                if segment.lower().endswith('.exe') and 'Image' not in event:
                    event['Image'] = segment
        return event

    def get_enrichment_stats(self) -> dict:
        """Return a summary of enrichment activity since initialization."""
        total = len(self._enrichment_log)
        enriched = sum(1 for e in self._enrichment_log if e['tokens_added'])
        return {
            'total_events': total,
            'enriched': enriched,
            'enrichment_rate': round(enriched / total, 3) if total else 0.0,
        }

    # ── ForensicBrain-compatible proxy interface ──────────────────────────
    # brain.py calls next_technique(), last_raw_event, evasions, evolve()
    # directly on self.red, so MordorEnricher must expose them.

    def next_technique(self, benign_ratio: float = 0.3) -> tuple:
        """Alias for next_enriched() — satisfies ForensicBrain interface."""
        return self.next_enriched(benign_ratio)

    @property
    def last_raw_event(self) -> dict:
        return self.agent.last_raw_event

    @property
    def evasions(self) -> dict:
        return self.agent.evasions

    @evasions.setter
    def evasions(self, val):
        self.agent.evasions = val

    def evolve(self, technique_id: str, caught_by_patterns):
        return self.agent.evolve(technique_id, caught_by_patterns)
