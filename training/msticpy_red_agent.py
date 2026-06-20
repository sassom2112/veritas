"""
msticpy_red_agent.py — Phase 1: MSTICPy-powered Red Agent.

Uses MordorDriver.search_queries() to enumerate datasets per MITRE technique,
maps discovered names to local JSONL files, and merges the extra events into
the fallback MordorRedAgent's event pool.

Falls back gracefully if MSTICPy is unavailable or yields no new coverage.
Compatible with MordorEnricher (same interface: next_technique, last_raw_event,
evasions, evolve).
"""
import json
import os
import random

# Sub-technique → folder that holds its Mordor JSONL files locally
_TECHNIQUE_FOLDER = {
    'T1569.002': 'lateral_movement',
    'T1547.001': 'persistence',
    'T1003.001': 'credential_access',
    'T1036.005': 'defense_evasion',
    'T1087.001': 'discovery',
    'T1059.001': 'execution',
    'T1560.001': 'collection',
    'T1548.002': 'privilege_escalation',
}

# MSTICPy search uses base technique IDs (no sub-technique suffix)
_MITRE_BASE = {tid: tid.split('.')[0] for tid in _TECHNIQUE_FOLDER}


def _load_jsonl(filepath):
    events = []
    try:
        with open(filepath) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return events


class MSTICPyRedAgent:
    """
    Wraps MordorRedAgent with MSTICPy-driven dataset discovery.

    At init, queries MordorDriver.search_queries() for each technique,
    checks local datasets/ tree for matching JSONL files, and augments
    the fallback event pools with any new files found.

    If MSTICPy is unavailable or network discovery fails the agent is
    transparent — next_technique() behaves identically to the fallback.
    """

    def __init__(self, mordor_fallback):
        self.fallback = mordor_fallback
        self._project_root = mordor_fallback.project_root
        # Extra events discovered via MSTICPy (merged into fallback pools)
        self._augmented: dict[str, int] = {}  # technique_id → count added
        self._try_msticpy_discovery()

    # ── MSTICPy discovery ────────────────────────────────────────────────
    def _try_msticpy_discovery(self):
        try:
            from msticpy.data.drivers.mordor_driver import MordorDriver
        except ImportError:
            print("  ℹ️  MSTICPy not available — file-based agent only")
            return

        print("  🔍 MSTICPy MordorDriver: connecting (downloads metadata)...")
        try:
            driver = MordorDriver()
            driver.connect()
        except Exception as exc:
            print(f"  ⚠️  MordorDriver.connect() failed: {exc}")
            return

        # Index every local JSONL file by stem so we can skip files
        # that are already loaded AND discover truly new ones.
        datasets_root = os.path.join(self._project_root, 'datasets')
        local_index: dict[str, str] = {}  # stem → full path
        if os.path.isdir(datasets_root):
            for subdir in os.listdir(datasets_root):
                subpath = os.path.join(datasets_root, subdir)
                if not os.path.isdir(subpath):
                    continue
                for fname in os.listdir(subpath):
                    if fname.endswith('.json') or fname.endswith('.jsonl'):
                        stem = os.path.splitext(fname)[0]
                        local_index[stem] = os.path.join(subpath, fname)

        # Basenames already wired into DATASET_MAP (already loaded by fallback)
        try:
            from mordor_agent import DATASET_MAP
        except ImportError:
            DATASET_MAP = {}

        already_loaded: set[str] = set()
        for config in DATASET_MAP.values():
            raw_paths = config.get('files', [config['file']] if 'file' in config else [])
            for p in raw_paths:
                already_loaded.add(os.path.splitext(os.path.basename(p))[0])

        total_extra = 0
        for tech_id, base_id in _MITRE_BASE.items():
            try:
                discovered = driver.search_queries(base_id)
            except Exception:
                continue
            if not discovered:
                continue

            added = 0
            for ds_name in discovered:
                # MSTICPy may return "mordor://name" or plain "name"
                stem = ds_name.split('/')[-1]
                if stem in already_loaded:
                    continue  # already in baseline event pool

                if stem in local_index:
                    # New local file — load and merge into fallback pool
                    events = _load_jsonl(local_index[stem])
                    if events:
                        self.fallback.events.setdefault(tech_id, []).extend(events)
                        added += len(events)
                        print(f"  ✅ MSTICPy+local [{tech_id}]: +{len(events)} "
                              f"from {stem}")
                    continue

                # Not local — try MordorDriver.query() (may download from GitHub)
                try:
                    df = driver.query(ds_name)
                    if df is not None and not df.empty:
                        records = df.to_dict('records')
                        self.fallback.events.setdefault(tech_id, []).extend(records)
                        added += len(records)
                        print(f"  ✅ MSTICPy download [{tech_id}]: +{len(records)} "
                              f"from {stem}")
                except Exception:
                    pass  # PCAP or unsupported format — silently skip

            if added:
                self._augmented[tech_id] = added
                total_extra += added

        if total_extra:
            print(f"  📊 MSTICPy augmented {total_extra} additional events "
                  f"across {len(self._augmented)} techniques")
        else:
            print("  ℹ️  MSTICPy discovery: no new datasets found "
                  "(all techniques already covered by local files)")

    # ── Red agent interface (mirrors MordorRedAgent) ─────────────────────
    @property
    def last_raw_event(self) -> dict:
        return self.fallback.last_raw_event

    @last_raw_event.setter
    def last_raw_event(self, val):
        self.fallback.last_raw_event = val

    @property
    def evasions(self) -> dict:
        return self.fallback.evasions

    @evasions.setter
    def evasions(self, val):
        self.fallback.evasions = val

    def next_technique(self, benign_ratio=0.3):
        # Delegate entirely — discovery already merged extra events into
        # fallback.events, so the fallback naturally draws from augmented pool.
        return self.fallback.next_technique(benign_ratio)

    def evolve(self, technique_id, caught_by_patterns):
        return self.fallback.evolve(technique_id, caught_by_patterns)

    def cleanup(self, technique_id):
        self.fallback.cleanup(technique_id)

    def get_augmentation_summary(self) -> dict:
        return dict(self._augmented)
