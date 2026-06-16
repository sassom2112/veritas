import json
import random
import os

# ── MITRE technique mapping to dataset files ────────────────────
# Each entry supports either 'file' (single path) or 'files' (list of paths).
# Multiple files for the same technique are merged into one event pool.
DATASET_MAP = {
    # ── Original 5 techniques ────────────────────────────────────
    'T1569.002': {
        'name': 'PsExec',
        'file': 'datasets/lateral_movement/empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json',
        'key_fields': ['TargetImage', 'SourceImage', 'CallTrace', 'GrantedAccess']
    },
    'T1547.001': {
        'name': 'Registry Run Key',
        'file': 'datasets/persistence/empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json',
        'key_fields': ['TargetObject', 'Details', 'EventType']
    },
    'T1003.001': {
        'name': 'Credential Dumping',
        'file': 'datasets/credential_access/empire_mimikatz_logonpasswords_2020-08-07103224.json',
        'key_fields': ['TargetImage', 'SourceImage', 'GrantedAccess', 'CallTrace']
    },
    'T1036.005': {
        'name': 'Masquerading / DLL Injection',
        'file': 'datasets/defense_evasion/empire_dllinjection_LoadLibrary_CreateRemoteThread_2020-07-22000048.json',
        'key_fields': ['SourceImage', 'TargetImage', 'StartAddress', 'StartModule']
    },
    # T1071.001 signals are IOC-based (IPs); no Mordor dataset file needed

    # ── New 4 techniques ─────────────────────────────────────────
    'T1087.001': {
        'name': 'Account Discovery: Local Account',
        'files': [
            'datasets/discovery/empire_shell_samr_EnumDomainUsers_2020-09-21193527.json',
            'datasets/discovery/cmd_seatbelt_group_user_2020-11-0216391814.json',
            'datasets/discovery/empire_shell_net_local_users_2020-09-21192606.json',
            'datasets/discovery/empire_shell_net_localgroup_administrators_2020-09-21191843.json',
            'datasets/discovery/empire_shell_rpc_samr_smb_group_domain_admins_standard_user_2020-09-21040850.json',
            'datasets/discovery/empire_getsession_dcerpc_smb_srvsvc_NetSessEnum_2020-09-22034513.json',
        ],
        'key_fields': ['CommandLine', 'Image', 'TargetObject', 'AccountName']
    },
    'T1059.001': {
        'name': 'Command and Scripting: PowerShell / VBS',
        'files': [
            'datasets/execution/empire_launcher_vbs_2020-09-04160940.json',
            'datasets/execution/psh_python_webserver_2020-10-2900161507.json',
            'datasets/execution/cmd_sharpview_pcre_net_2020-10-2920232423.json',
            'datasets/execution/psh_powershell_httplistener_2020-11-0204130683.json',
        ],
        'key_fields': ['CommandLine', 'Image', 'TargetFilename', 'ScriptBlockText']
    },
    'T1560.001': {
        'name': 'Archive Collected Data',
        'files': [
            'datasets/collection/msf_record_mic_2020-06-09225055.json',
        ],
        'key_fields': ['Image', 'TargetObject', 'TargetFilename', 'Details']
    },
    'T1548.002': {
        'name': 'UAC Bypass',
        'files': [
            'datasets/privilege_escalation/empire_uac_shellapi_fodhelper_2020-09-04032946.json',
            'datasets/privilege_escalation/cmd_service_mod_fax_2020-10-2120454410.json',
        ],
        'key_fields': ['Image', 'CommandLine', 'IntegrityLevel', 'TargetObject']
    },
}

# ── Benign event signatures ─────────────────────────────────────
# Real Windows behavior that looks suspicious but isn't
BENIGN_TEMPLATES = [
    # Legitimate process access
    {
        'EventID': 10,
        'SourceImage': 'C:\\Windows\\System32\\MsMpEng.exe',
        'TargetImage': 'C:\\Windows\\System32\\svchost.exe',
        'GrantedAccess': '0x1000',
        'Category': 'Process accessed',
        'AccountName': 'SYSTEM',
        'label': 'benign'
    },
    # Legitimate registry modification
    {
        'EventID': 13,
        'TargetObject': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive',
        'Details': 'C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe',
        'EventType': 'SetValue',
        'AccountName': 'user',
        'label': 'benign'
    },
    # Windows Defender scan
    {
        'EventID': 10,
        'SourceImage': 'C:\\Program Files\\Windows Defender\\MsMpEng.exe',
        'TargetImage': 'C:\\Windows\\System32\\lsass.exe',
        'GrantedAccess': '0x1000',
        'Category': 'Process accessed',
        'label': 'benign'
    },
    # Legitimate admin psexec
    {
        'EventID': 1,
        'Image': 'C:\\Windows\\System32\\services.exe',
        'CommandLine': 'C:\\Windows\\System32\\services.exe',
        'ParentImage': 'C:\\Windows\\System32\\wininit.exe',
        'AccountName': 'SYSTEM',
        'label': 'benign'
    },
    # Windows Update
    {
        'EventID': 13,
        'TargetObject': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update',
        'Details': 'DWORD (0x00000004)',
        'EventType': 'SetValue',
        'label': 'benign'
    },
    # Edge autolaunch
    {
        'EventID': 13,
        'TargetObject': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftEdgeAutoLaunch',
        'Details': 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
        'EventType': 'SetValue',
        'label': 'benign'
    },
    # Legitimate svchost network connection
    {
        'EventID': 3,
        'Image': 'C:\\Windows\\System32\\svchost.exe',
        'DestinationIp': '20.42.65.90',
        'DestinationPort': 443,
        'Initiated': 'true',
        'AccountName': 'NETWORK SERVICE',
        'label': 'benign'
    },
    # Task scheduler
    {
        'EventID': 1,
        'Image': 'C:\\Windows\\System32\\taskhost.exe',
        'CommandLine': 'taskhost.exe',
        'ParentImage': 'C:\\Windows\\System32\\svchost.exe',
        'AccountName': 'user',
        'label': 'benign'
    },
]


class MordorRedAgent:
    """
    Real Red Agent using OTRF/Mordor Security Datasets.
    23,231 real Sysmon events from actual attack executions.
    Provides both attack AND benign Windows host telemetry.
    Replaces SimulatedRedAgent for production accuracy metrics.
    """
    def __init__(self, project_root='~/find-evil-2026'):
        self.project_root = os.path.expanduser(project_root)
        self.events = {}
        self.evasions = {}
        self.current_index = 0
        self.last_raw_event: dict = {}  # raw Sysmon dict for the most recent event
        self.load_datasets()

    def load_datasets(self):
        """Load all JSONL datasets into memory. Supports 'file' or 'files' per technique."""
        total = 0
        for technique_id, config in DATASET_MAP.items():
            # Normalise to a list regardless of whether 'file' or 'files' was used
            raw_paths = config.get('files', [config['file']] if 'file' in config else [])
            paths = [os.path.join(self.project_root, p) for p in raw_paths]

            events = []
            missing = []
            for filepath in paths:
                try:
                    with open(filepath) as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    events.append(json.loads(line))
                                except json.JSONDecodeError:
                                    pass
                except FileNotFoundError:
                    missing.append(os.path.basename(filepath))

            self.events[technique_id] = events
            total += len(events)
            src_count = len(paths) - len(missing)
            label = f"{src_count}/{len(paths)} files" if len(paths) > 1 else ""
            if missing:
                print(f"  ⚠️  {technique_id}: {len(events)} events ({', '.join(missing)} missing)")
            else:
                print(f"  ✅ {technique_id}: {len(events)} events loaded {label}".rstrip())

        print(f"  📊 Total: {total} real Sysmon events loaded")

    def next_technique(self, benign_ratio=0.3):
        """
        30% benign, 70% attack.
        Benign comes from real Windows behavior templates.
        Attack comes from real Mordor Sysmon logs.
        """
        if random.random() < benign_ratio:
            return 'BENIGN', self._get_benign()
        else:
            return self._get_attack()

    def _get_benign(self):
        """Return a real benign Windows event"""
        template = random.choice(BENIGN_TEMPLATES)
        self.last_raw_event = template
        return self._format_event(template)

    def _get_attack(self):
        """Return a real attack Sysmon event"""
        # Cycle through techniques
        ids = list(DATASET_MAP.keys())
        technique_id = ids[self.current_index % len(ids)]
        self.current_index += 1

        events = self.events.get(technique_id, [])
        if not events:
            self.last_raw_event = {}
            return technique_id, f"No events loaded for {technique_id}"

        # Use evolved evasion if available
        if technique_id in self.evasions and self.evasions[technique_id]:
            # Mix real events with evolved evasions
            if random.random() < 0.5:
                event = random.choice(events)
            else:
                evasion = random.choice(self.evasions[technique_id])
                self.last_raw_event = evasion
                return technique_id, evasion['modified_artifact']
        else:
            event = random.choice(events)

        self.last_raw_event = event
        return technique_id, self._format_event(event)

    def _format_event(self, event):
        """
        Convert Sysmon event to artifact description
        Blue Agent can score against.
        Extracts the most forensically relevant fields.
        """
        parts = []
        
        event_id = event.get('EventID', 0)
        
        # Process creation (EventID 1)
        if event_id == 1:
            if event.get('Image'):
                parts.append(f"Process={event['Image']}")
            if event.get('CommandLine'):
                parts.append(f"CommandLine={event['CommandLine'][:100]}")
            if event.get('ParentImage'):
                parts.append(f"Parent={event['ParentImage']}")
            if event.get('AccountName'):
                parts.append(f"User={event['AccountName']}")

        # Process access (EventID 10)
        elif event_id == 10:
            if event.get('SourceImage'):
                parts.append(f"Source={event['SourceImage']}")
            if event.get('TargetImage'):
                parts.append(f"Target={event['TargetImage']}")
            if event.get('GrantedAccess'):
                parts.append(f"Access={event['GrantedAccess']}")
            if event.get('CallTrace'):
                parts.append(f"CallTrace={event['CallTrace'][:100]}")

        # Registry value set (EventID 13)
        elif event_id == 13:
            if event.get('TargetObject'):
                parts.append(f"Registry={event['TargetObject']}")
            if event.get('Details'):
                parts.append(f"Value={event['Details'][:100]}")
            if event.get('EventType'):
                parts.append(f"Type={event['EventType']}")

        # Network connection (EventID 3)
        elif event_id == 3:
            if event.get('Image'):
                parts.append(f"Process={event['Image']}")
            if event.get('DestinationIp'):
                parts.append(f"DestIP={event['DestinationIp']}")
            if event.get('DestinationPort'):
                parts.append(f"DestPort={event['DestinationPort']}")

        # File creation (EventID 11)
        elif event_id == 11:
            if event.get('TargetFilename'):
                parts.append(f"File={event['TargetFilename']}")
            if event.get('Image'):
                parts.append(f"Process={event['Image']}")

        # CreateRemoteThread (EventID 8)
        elif event_id == 8:
            if event.get('SourceImage'):
                parts.append(f"Source={event['SourceImage']}")
            if event.get('TargetImage'):
                parts.append(f"Target={event['TargetImage']}")
            if event.get('StartAddress'):
                parts.append(f"StartAddr={event['StartAddress']}")

        # PowerShell script block (EventID 4103 / 800)
        elif event_id in (4103, 800):
            if event.get('ScriptBlockText'):
                parts.append(f"ScriptBlock={event['ScriptBlockText'][:120]}")
            if event.get('CommandLine'):
                parts.append(f"CommandLine={event['CommandLine'][:100]}")
            if event.get('Image'):
                parts.append(f"Process={event['Image']}")

        # Generic — CommandLine-bearing events not covered above
        elif event.get('CommandLine'):
            parts.append(f"CommandLine={event['CommandLine'][:100]}")
            if event.get('Image'):
                parts.append(f"Process={event['Image']}")
            if event.get('ParentImage'):
                parts.append(f"Parent={event['ParentImage']}")

        # Fallback — include any non-empty string fields
        else:
            for key in ['Image', 'TargetObject', 'TargetImage',
                       'CommandLine', 'Details', 'DestinationIp']:
                if event.get(key):
                    parts.append(f"{key}={event[key][:80]}")

        # Always include EventID and hostname
        parts.append(f"EventID={event_id}")
        if event.get('Hostname'):
            parts.append(f"Host={event['Hostname']}")

        return " | ".join(parts) if parts else str(event)[:200]

    def evolve(self, technique_id, caught_by_patterns):
        """Red evolves using Claude when caught"""
        import anthropic
        client = anthropic.Anthropic()
        
        events = self.events.get(technique_id, [])
        if not events:
            return
        
        sample_event = self._format_event(random.choice(events))
        
        try:
            response = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=400,
                messages=[{
                    "role": "user",
                    "content": f"""Red team operator analyzing a Sysmon detection.
Caught by patterns: {caught_by_patterns}
Sample real event: {sample_event}
Technique: {technique_id}

Suggest a modified artifact description that evades those patterns
while remaining realistic for Windows Sysmon telemetry.
Respond in JSON only, no markdown, no extra text:
{{"modified_artifact": "short description under 60 chars", "evasion": "what changed"}}"""
                }]
            )

            raw = response.content[0].text.strip()
            start, end = raw.find('{'), raw.rfind('}') + 1
            if start == -1 or end == 0 or start >= end:
                raise ValueError(f"no JSON in response: {raw[:80]!r}")
            suggestion = json.loads(raw[start:end])

            if technique_id not in self.evasions:
                self.evasions[technique_id] = []
            self.evasions[technique_id].append(suggestion)
            print(f"   🔴 Evolved: {suggestion['evasion'][:60]}")
            
        except Exception as e:
            print(f"   ⚠️  Evolve failed: {e}")

    def cleanup(self, technique_id):
        pass  # no cleanup needed for dataset-based agent


if __name__ == "__main__":
    # Test the agent
    agent = MordorRedAgent()
    
    print("\n── Sample attack events ──")
    for i in range(5):
        technique_id, artifact = agent.next_technique(benign_ratio=0)
        print(f"\n{technique_id}: {artifact[:120]}...")
    
    print("\n── Sample benign events ──")
    for i in range(3):
        _, artifact = agent.next_technique(benign_ratio=1.0)
        print(f"\nBENIGN: {artifact[:120]}...")