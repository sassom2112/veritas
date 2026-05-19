import os
import json
import time
import random
import anthropic
import subprocess
import matplotlib
matplotlib.use('Agg')  # non-interactive backend for SIFT
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from datetime import datetime, timezone
from mordor_agent import MordorRedAgent

# Resolve paths relative to this file so brain.py works from any cwd
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, '..'))
_REPORTS = os.path.join(_PROJECT_ROOT, 'reports')

def _api_call_with_retry(fn, max_retries=4, base_delay=10):
    """Retry an Anthropic API call on 529 overloaded errors with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as e:
            err_str = str(e)
            if ('529' in err_str or 'overloaded' in err_str.lower()) and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 3)
                print(f"   ⏳ API overloaded — retry {attempt + 1}/{max_retries - 1} in {delay:.1f}s")
                time.sleep(delay)
            else:
                raise
    return None


# Forensically verified IOCs — survive pruning and get half-weight on single match
PROTECTED_SIGNALS = [
    'psexesvc', 'psexec', 'mimikatz', 'hydrakatz',
    'lsass', '0x1fffff', 'dllhost\\\\svchost',
    '12.190.135.235', '199.73.28.114', 'winclient',
    'sekurlsa', 'spinlock', 'system4.rar',
    'eventid=7045', 'sc.exe create', '\\admin$\\',
    'invoke-expression', 'powershell -enc',
    'fodhelper', 'net user /domain', 'samr',
    'record_mic', 'audiocapture',
]

# ══════════════════════════════════════════════════════════════
#  THE ASL ARCHITECTURE (Adversarial Signal Learning)
#
#  Red Agent  = evasion generator  (creates attack artifacts)
#  Blue Agent = signal learner     (detects attack artifacts)
#
#  Red  gets better when Blue catches it   → evolve evasion
#  Blue gets better when Red evades it     → learn new patterns
#  Brain tracks the adversarial training loop
# ══════════════════════════════════════════════════════════════

class RedAgent:
    """
    The Generator.
    Creates attack artifacts and evolves them when caught.
    Goal: fool the Discriminator (Blue Agent).
    """
    def __init__(self):
        self.client = anthropic.Anthropic()
        
        # Starting techniques — seeded from nromanoff investigation
        self.techniques = {
            'T1547.001': {
                'name': 'Registry Run Key',
                'artifact': 'dllhost\\svchost.exe in HKLM Run key',
                'evasions': [],
                'generation': 0  # how many times it has evolved
            },
            'T1036.005': {
                'name': 'Masquerading',
                'artifact': '102400 byte svchost.exe in dllhost folder',
                'evasions': [],
                'generation': 0
            },
            'T1003.001': {
                'name': 'Credential Dumping',
                'artifact': 'hydrakatz.exe in System32',
                'evasions': [],
                'generation': 0
            },
            'T1071.001': {
                'name': 'C2 Web Protocol',
                'artifact': '12.190.135.235 in Netman registry key',
                'evasions': [],
                'generation': 0
            },
            'T1569.002': {
                'name': 'PsExec Lateral Movement',
                'artifact': 'PSEXESVC.EXE in Windows root',
                'evasions': [],
                'generation': 0
            },
        }
        self.current_index = 0

    def next_technique(self):
        """
        Cycle through techniques.
        Use latest evasion if one exists.
        """
        ids = list(self.techniques.keys())
        technique_id = ids[self.current_index % len(ids)]
        self.current_index += 1
        
        data = self.techniques[technique_id]
        
        # Use most evolved artifact if available
        if data['evasions']:
            artifact = data['evasions'][-1]['modified_artifact']
        else:
            artifact = data['artifact']
            
        return technique_id, artifact

    def evolve(self, technique_id, caught_by_patterns):
        """
        Generator loss function:
        Red was caught → must evolve to fool Discriminator.
        """
        print(f"\n🔴 Red evolving {technique_id} (gen {self.techniques[technique_id]['generation']})...")
        
        try:
            response = _api_call_with_retry(lambda: self.client.messages.create(
                model="claude-opus-4-5",
                max_tokens=300,
                messages=[{
                    "role": "user",
                    "content": f"""You are a red team attacker.
Your artifact was detected by these patterns: {caught_by_patterns}
Technique: {technique_id}
Current artifact: {self.techniques[technique_id]['artifact']}

Suggest ONE realistic Windows evasion that avoids those patterns.
Respond in JSON only, no markdown:
{{"modified_artifact": "description", "evades": "which pattern avoided"}}"""
                }]
            ))

            raw = response.content[0].text.strip()
            start, end = raw.find('{'), raw.rfind('}') + 1
            suggestion = json.loads(raw[start:end])
            self.techniques[technique_id]['evasions'].append(suggestion)
            self.techniques[technique_id]['generation'] += 1
            print(f"   🔴 New artifact: {suggestion['modified_artifact']}")
            return suggestion

        except Exception as e:
            print(f"   ⚠️  Red evolve failed: {e}")
            return None


class BlueAgent:
    """
    The Discriminator.
    Detects attack artifacts and learns when it misses.
    Goal: correctly classify real vs malicious artifacts.
    """
    def __init__(self):
        self.client = anthropic.Anthropic()
        
        # Detection patterns with weights
        # Sysmon-aware signals for real Mordor telemetry
        self.patterns = {
            'T1547.001': {
                'name': 'Registry Run Key',
                'signals': ['dllhost\\\\svchost', 'psexesvc',
                            'runonce', '\\cv\\run'],
                'weight': 35,
            },
            'T1036.005': {
                'name': 'Masquerading',
                'signals': ['createremotethread', 'loadlibrary',
                            'eventid=8', 'startaddress',
                            '102400', 'dllhost\\\\svchost.exe'],
                'weight': 35,
            },
            'T1003.001': {
                'name': 'Credential Dumping',
                'signals': ['mimikatz', 'hydrakatz', 'sekurlsa',
                            '0x1fffff', 'access=0x1410'],
                'weight': 35,
            },
            'T1071.001': {
                'name': 'C2 Web Protocol',
                'signals': ['12.190.135.235', '199.73.28.114', 'winclient'],
                'weight': 35,
            },
            'T1569.002': {
                'name': 'PsExec',
                'signals': ['psexesvc', 'psexec', 'svcctl',
                            '\\admin$\\'],
                'weight': 35,
            },
            'T1087.001': {
                'name': 'Account Discovery',
                'signals': ['net.exe user', 'net user /domain', 'seatbelt',
                            'enumdomainusers', 'samr', 'net localgroup',
                            'getdomaingroup', 'netsessenum'],
                'weight': 35,
            },
            'T1059.001': {
                'name': 'PowerShell / VBS Execution',
                'signals': ['wscript.exe', 'cscript.exe',
                            'powershell -enc', 'invoke-expression',
                            'sharpview', 'netsh advfirewall'],
                'weight': 35,
            },
            'T1560.001': {
                'name': 'Archive Collected Data',
                'signals': ['record_mic', 'audiocapture',
                            'rar.exe', '7z.exe'],
                'weight': 35,
            },
            'T1548.002': {
                'name': 'UAC Bypass',
                'signals': ['fodhelper', 'sdclt.exe',
                            'integritylevel=high', 'fax service'],
                'weight': 35,
            },
        }

    def discriminate(self, artifact_description):
        """
        Core discriminator function.
        Conjunction scoring: 2+ signals = full weight,
        1 protected signal = half weight, 1 generic signal = 0.
        Returns score, matched techniques, reasons.
        """
        text = artifact_description.lower().replace('\\\\', '\\')

        if 'anthropic_api_key' in text:
            return 0, {}, []

        total_score = 0
        matched = {}
        reasons = []

        for technique_id, data in self.patterns.items():
            hit_signals = [
                s for s in data['signals']
                if s.lower().replace('\\\\', '\\') in text
            ]
            if not hit_signals:
                continue

            if len(hit_signals) >= 2:
                weight = data['weight']
            else:
                is_protected = any(
                    p.lower() in hit_signals[0].lower()
                    for p in PROTECTED_SIGNALS
                )
                weight = data['weight'] // 2 if is_protected else 0

            if weight > 0:
                total_score += weight
                matched[technique_id] = hit_signals
                reasons.append(
                    f"{data['name']} (+{weight}) via: {hit_signals}"
                )

        return total_score, matched, reasons

    def learn(self, technique_id, missed_artifact, raw_event=None):
        """
        Discriminator loss function: Blue missed → must learn new pattern.
        When raw_event is provided, Claude is grounded in actual Sysmon
        field values rather than guessing from the formatted string.
        """
        print(f"\n🔵 Blue learning from missed {technique_id}...")

        # Build a concise view of the raw event — drop large/noisy fields
        _SKIP = {'tags', '@version', '@timestamp', 'EventReceivedTime',
                 'SourceModuleName', 'SourceModuleType', 'ProviderGuid',
                 'RecordNumber', 'ProcessGuid', 'ThreadID', 'Keywords',
                 'SeverityValue', 'Severity', 'Opcode', 'Channel',
                 'ExecutionProcessID', 'EventTime', 'port', 'host',
                 'UtcTime', 'Version', 'Task', 'RuleName'}
        if raw_event and isinstance(raw_event, dict):
            compact = {k: v for k, v in raw_event.items()
                       if k not in _SKIP and v not in ('', None, [], {})}
            raw_context = (
                f"Raw Sysmon event fields:\n"
                f"{json.dumps(compact, indent=2, default=str)[:800]}\n\n"
                "Extract ONE specific field value from the raw event above "
                "that would reliably identify this technique. "
                "The value MUST be a real string from the event, not invented."
            )
        else:
            raw_context = (
                "No raw event available. "
                "Suggest a short, specific string pattern likely to appear "
                "in real Sysmon telemetry for this technique."
            )

        try:
            response = _api_call_with_retry(lambda: self.client.messages.create(
                model="claude-opus-4-5",
                max_tokens=200,
                messages=[{
                    "role": "user",
                    "content": (
                        f"You are a blue team defender. "
                        f"This attack artifact was NOT detected:\n"
                        f"  Formatted: {missed_artifact}\n"
                        f"  Technique: {technique_id}\n"
                        f"  Current signals: {self.patterns[technique_id]['signals']}\n\n"
                        f"{raw_context}\n\n"
                        "Respond in JSON only, no markdown:\n"
                        '{"new_signal": "exact_value_to_search_for"}'
                    )
                }]
            ))

            raw = response.content[0].text.strip()
            start, end = raw.find('{'), raw.rfind('}') + 1
            if start == -1 or end == 0 or start >= end:
                raise ValueError(f"no JSON in response: {raw[:80]!r}")
            suggestion = json.loads(raw[start:end])
            new_signal = suggestion['new_signal'].strip()

            # Reject compound logic, wildcards, and empty/technique-ID signals
            import re as _re
            if (not new_signal
                    or ' AND ' in new_signal.upper()
                    or ' OR ' in new_signal.upper()
                    or '.*' in new_signal
                    or _re.match(r'^T\d{4}', new_signal)
                    or new_signal in self.patterns[technique_id]['signals']):
                print(f"   ⚠️  Rejected signal (compound/wildcard/duplicate): "
                      f"'{new_signal[:50]}'")
                return None

            self.patterns[technique_id]['signals'].append(new_signal)
            print(f"   🔵 Learned: '{new_signal}'")
            return new_signal

        except Exception as e:
            print(f"   ⚠️  Blue learn failed: {e}")
            return None

    def tune_weights(self, performance_history):
        """
        Adjust detection weights based on recent performance, then prune
        signals that never appear in real attack artifacts.
        Protected signals survive pruning regardless of firing rate.
        """
        # Forensically verified IOCs from real case investigations —
        # must survive pruning even if rare in Mordor training data
        for technique_id in self.patterns:
            recent = [
                h for h in performance_history[-10:]
                if h['technique'] == technique_id
            ]
            if len(recent) < 2:
                continue

            # ── Weight tuning ──────────────────────────────────────
            hit_rate = sum(1 for r in recent if r['detected']) / len(recent)
            old = self.patterns[technique_id]['weight']
            if hit_rate > 0.8:
                self.patterns[technique_id]['weight'] = min(old + 5, 50)
            elif hit_rate < 0.3:
                self.patterns[technique_id]['weight'] = max(old - 5, 28)

            # ── Signal pruning ─────────────────────────────────────
            # Only prune after enough observations of this technique
            tech_history = [
                h for h in performance_history
                if h['technique'] == technique_id
            ]
            if len(tech_history) < 15:
                continue

            recent_artifacts = [
                h['artifact'].lower()
                for h in tech_history[-50:]
            ]
            active_signals = []
            for signal in self.patterns[technique_id]['signals']:
                ever_fired = any(
                    signal.lower() in art for art in recent_artifacts
                )
                is_protected = any(
                    p.lower() in signal.lower()
                    for p in PROTECTED_SIGNALS
                )
                if ever_fired or is_protected:
                    active_signals.append(signal)
                else:
                    print(f"   ✂️  Pruned [{technique_id}]: '{signal[:60]}'")

            if active_signals:  # never prune to empty
                self.patterns[technique_id]['signals'] = active_signals

class ForensicBrain:
    """
    The ASL Training Loop.
    Coordinates Red vs Blue, tracks metrics, generates graphs.

    Three optional enhancement layers (all fail-safe):
      Phase 1 — MSTICPyRedAgent: dynamic MordorDriver dataset discovery
      Phase 2 — MordorEnricher:  per-event enrichment tokens (LSASS, C2, etc.)
      Phase 3 — PatternDatabase: SQLite pattern store with hit/miss tracking
    """
    def __init__(self):
        # ── Phase 1: MSTICPy dataset discovery ──────────────────────────
        mordor = MordorRedAgent(project_root=_PROJECT_ROOT)
        try:
            from msticpy_red_agent import MSTICPyRedAgent
            red_agent = MSTICPyRedAgent(mordor)
            print("🔍 Phase 1: MSTICPy Red Agent active")
        except Exception as exc:
            print(f"⚠️  Phase 1: MSTICPy agent unavailable ({exc}) — file-only")
            red_agent = mordor

        # ── Phase 2: Enrichment tokens ──────────────────────────────────
        try:
            from msticpy_enrichment import MordorEnricher
            self.red = MordorEnricher(red_agent)
            print("🔬 Phase 2: MordorEnricher active")
        except Exception as exc:
            print(f"⚠️  Phase 2: Enrichment unavailable ({exc})")
            self.red = red_agent

        # ── Phase 3: SQLite pattern database ────────────────────────────
        try:
            from pattern_db import PatternDatabase
            self.db = PatternDatabase()
            stats = self.db.get_stats()
            print(f"💾 Phase 3: PatternDB active — "
                  f"{stats['total_signals']} signals, "
                  f"{stats['training_runs']} training runs")
        except Exception as exc:
            print(f"⚠️  Phase 3: PatternDB unavailable ({exc}) — JSON state only")
            self.db = None

        self.blue = BlueAgent()
        self.history = []
        self.iteration = 0
        self.metrics = {
            'iterations': [],
            'blue_scores': [],
            'detection_flags': [],    # 1=detected, 0=missed
            'red_generations': [],
            'blue_pattern_counts': [],
            'weights': {t: [] for t in self.blue.patterns}
        }

    def run(self, max_iterations=100):
        """
        Main ASL training loop.
        Hard cap at max_iterations — prevents runaway execution.
        Hackathon requirement: must have termination condition.
        """
        print(f"\n{'═'*60}")
        print(f"  FORENSIC ASL TRAINING — {max_iterations} iterations")
        print(f"{'═'*60}")
        
        self.load_state()
        
        for i in range(max_iterations):
            self.iteration += 1
            print(f"\n── Iteration {self.iteration}/{max_iterations} ──")
            
            # ── RED: Generate artifact ──────────────────────────
            technique_id, artifact = self.red.next_technique()
            print(f"🔴 Red: {technique_id} — {artifact[:60]}...")
            
            # ── BLUE: Discriminate ──────────────────────────────
            score, matched, reasons = self.blue.discriminate(artifact)
            detected = score >= 40
            
            print(f"🔵 Blue score: {score} — "
                  f"{'✅ DETECTED' if detected else '❌ MISSED'}")
            
            # ── RECORD ─────────────────────────────────────────
            record = {
                'iteration': self.iteration,
                'technique': technique_id,
                'artifact': artifact,
                'score': score,
                'detected': detected,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            self.history.append(record)
            
            # ── TRACK METRICS ───────────────────────────────────
            self.metrics['iterations'].append(self.iteration)
            self.metrics['blue_scores'].append(score)
            self.metrics['detection_flags'].append(1 if detected else 0)
            self.metrics['red_generations'].append(
                len(self.red.evasions.get(technique_id, []))
            )
            self.metrics['blue_pattern_counts'].append(
                sum(len(d['signals']) for d in self.blue.patterns.values())
            )
            for t, d in self.blue.patterns.items():
                self.metrics['weights'][t].append(d['weight'])
            
            # ── ADVERSARIAL LEARNING ────────────────────────────
            if technique_id == 'BENIGN':
                if detected:
                    print("   ⚠️  False positive on benign event — penalizing firing signals")
                    for tid, sigs in matched.items():
                        for sig in sigs:
                            if any(p.lower() in sig.lower() for p in PROTECTED_SIGNALS):
                                continue
                            old_w = self.blue.patterns[tid]['weight']
                            self.blue.patterns[tid]['weight'] = max(old_w - 3, 28)
            elif detected:
                # Red must evolve — caught
                caught_by = [
                    s for sigs in matched.values() for s in sigs
                ]
                self.red.evolve(technique_id, caught_by)
            else:
                # Blue must learn — missed; pass raw event for grounded learning
                self.blue.learn(technique_id, artifact,
                                self.red.last_raw_event)
            
            # ── TUNE WEIGHTS every 10 iterations ───────────────
            if self.iteration % 5 == 0:
                self.blue.tune_weights(self.history)
                self._print_scoreboard()
            
            self.save_state()
        
        # ── FINAL OUTPUT ────────────────────────────────────────
        print(f"\n{'═'*60}")
        print(f"  TRAINING COMPLETE — {max_iterations} iterations")
        print(f"{'═'*60}")
        self._print_scoreboard()
        self.plot_training(save=True)
        self.accuracy_report()

    def _print_scoreboard(self):
        """Live scoreboard during training"""
        recent = self.history[-20:] if len(self.history) >= 20 else self.history
        detection_rate = sum(1 for r in recent if r['detected']) / len(recent)
        
        print(f"\n📊 Scoreboard (last {len(recent)} rounds):")
        print(f"   Blue detection rate: {detection_rate:.0%}")
        print(f"   Total patterns: "
              f"{sum(len(d['signals']) for d in self.blue.patterns.values())}")
        
        for t, d in self.blue.patterns.items():
            recent_t = [r for r in recent if r['technique'] == t]
            if recent_t:
                rate = sum(1 for r in recent_t if r['detected']) / len(recent_t)
                print(f"   {t}: {rate:.0%} detection | "
                      f"weight={d['weight']} | "
                      f"signals={len(d['signals'])}")

    def plot_training(self, save=True):
        """
        Generate training graphs for hackathon submission.
        Shows the ASL adversarial dynamic visually.
        """
        if len(self.metrics['iterations']) < 2:
            print("⚠️  Need more iterations for graphs")
            return

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(
            'Forensic ASL Training — Red vs Blue Agent',
            fontsize=16, fontweight='bold'
        )

        iters = self.metrics['iterations']

        # ── Graph 1: Detection Score Over Time ─────────────────
        ax1 = axes[0, 0]
        ax1.plot(iters, self.metrics['blue_scores'],
                 color='#2196F3', alpha=0.4, linewidth=1)
        
        # Rolling average
        window = min(10, len(iters))
        rolling = np.convolve(
            self.metrics['blue_scores'],
            np.ones(window)/window, mode='valid'
        )
        ax1.plot(
            iters[window-1:], rolling,
            color='#1565C0', linewidth=2.5,
            label=f'{window}-iter rolling avg'
        )
        ax1.axhline(y=40, color='orange', linestyle='--',
                    linewidth=1.5, label='Detection threshold (40)')
        ax1.axhline(y=70, color='red', linestyle='--',
                    linewidth=1.5, label='High confidence (70)')
        ax1.set_title('Blue Agent Detection Score', fontweight='bold')
        ax1.set_xlabel('Iteration')
        ax1.set_ylabel('Score (0-100)')
        ax1.legend(fontsize=8)
        ax1.set_ylim(0, 110)
        ax1.fill_between(iters, self.metrics['blue_scores'],
                         alpha=0.1, color='#2196F3')

        # ── Graph 2: Detection Rate (Win/Loss) ──────────────────
        ax2 = axes[0, 1]
        flags = self.metrics['detection_flags']
        
        # Rolling detection rate
        win = min(10, len(flags))
        rolling_rate = [
            sum(flags[max(0, i-win):i+1]) / min(i+1, win)
            for i in range(len(flags))
        ]
        ax2.plot(iters, rolling_rate,
                 color='#4CAF50', linewidth=2.5)
        ax2.fill_between(iters, rolling_rate, alpha=0.2, color='#4CAF50')
        
        # Mark detected vs missed
        for i, (it, flag) in enumerate(zip(iters, flags)):
            color = '#4CAF50' if flag else '#f44336'
            ax2.scatter(it, flag, color=color, alpha=0.5, s=20, zorder=5)
        
        ax2.axhline(y=0.5, color='gray', linestyle='--', linewidth=1)
        ax2.set_title('Detection Rate Over Time', fontweight='bold')
        ax2.set_xlabel('Iteration')
        ax2.set_ylabel('Detection Rate')
        ax2.set_ylim(-0.1, 1.1)
        
        detected_patch = mpatches.Patch(color='#4CAF50', label='Detected')
        missed_patch = mpatches.Patch(color='#f44336', label='Missed')
        ax2.legend(handles=[detected_patch, missed_patch], fontsize=8)

        # ── Graph 3: Red Evolution vs Blue Learning ─────────────
        ax3 = axes[1, 0]
        ax3_twin = ax3.twinx()
        
        l1, = ax3.plot(iters, self.metrics['red_generations'],
                       color='#f44336', linewidth=2.5,
                       label='Red generations (evasions)')
        l2, = ax3_twin.plot(iters, self.metrics['blue_pattern_counts'],
                            color='#2196F3', linewidth=2.5,
                            linestyle='--',
                            label='Blue patterns learned')
        
        ax3.set_title('ASL Arms Race — Red Evasions vs Blue Patterns',
                      fontweight='bold')
        ax3.set_xlabel('Iteration')
        ax3.set_ylabel('Red Generations', color='#f44336')
        ax3_twin.set_ylabel('Blue Pattern Count', color='#2196F3')
        ax3.legend(handles=[l1, l2], fontsize=8, loc='upper left')

        # ── Graph 4: Weight Evolution Per Technique ─────────────
        ax4 = axes[1, 1]
        _palette = ['#E91E63', '#9C27B0', '#FF9800', '#009688', '#795548',
                    '#2196F3', '#FF5722', '#607D8B', '#8BC34A']

        for (technique_id, weights), color in zip(
            self.metrics['weights'].items(), _palette
        ):
            if weights:
                ax4.plot(iters[:len(weights)], weights,
                         label=technique_id, color=color,
                         linewidth=2, marker='o',
                         markersize=3, markevery=5)
        
        ax4.set_title('Detection Weight Evolution Per Technique',
                      fontweight='bold')
        ax4.set_xlabel('Iteration')
        ax4.set_ylabel('Weight')
        ax4.legend(fontsize=7, loc='upper right')
        ax4.set_ylim(0, 60)

        plt.tight_layout()
        
        if save:
            path = os.path.join(_REPORTS, 'training_graphs.png')
            os.makedirs(_REPORTS, exist_ok=True)
            plt.savefig(path, dpi=150, bbox_inches='tight')
            print(f"\n📊 Graphs saved to {path}")
        
        plt.close()

    def accuracy_report(self):
        """Generate and save submission-ready accuracy report"""
        if not self.history:
            return {}

        report = {
            'generated': datetime.now(timezone.utc).isoformat()
,
            'total_iterations': self.iteration,
            'techniques': {},
            'overall': {}
        }

        total_hits = total_tests = 0

        for technique_id, data in self.blue.patterns.items():
            tests = [r for r in self.history
                     if r['technique'] == technique_id]
            if not tests:
                continue
            
            hits = sum(1 for r in tests if r['detected'])
            total_hits += hits
            total_tests += len(tests)
            hit_rate = hits / len(tests)

            report['techniques'][technique_id] = {
                'name': data['name'],
                'detection_rate': f"{hit_rate:.0%}",
                'hits': hits,
                'misses': len(tests) - hits,
                'final_weight': data['weight'],
                'patterns_learned': len(data['signals']),
                'red_evasions': len(
                    self.red.evasions.get(technique_id, [])
                )
            }

        # False positives: BENIGN events that were flagged as malicious
        benign_tests = [r for r in self.history if r['technique'] == 'BENIGN']
        false_positives = sum(1 for r in benign_tests if r['detected'])

        if total_tests:
            overall_rate = total_hits / total_tests
            # Precision = TP / (TP + FP)
            tp = total_hits
            fp = false_positives
            fn = total_tests - total_hits
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall / (precision + recall)
                  if (precision + recall) > 0 else 0.0)
            report['overall'] = {
                'detection_rate': f"{overall_rate:.0%}",
                'total_tests': total_tests,
                'total_detections': total_hits,
                'total_misses': total_tests - total_hits,
                'false_positives': false_positives,
                'benign_tests': len(benign_tests),
                'precision': f"{precision:.0%}",
                'recall': f"{recall:.0%}",
                'f1_score': f"{f1:.2f}",
            }

        os.makedirs(_REPORTS, exist_ok=True)
        with open(os.path.join(_REPORTS, 'accuracy_report.json'), 'w') as f:
            json.dump(report, f, indent=2)

        # Phase 3: record training run in PatternDB
        if self.db and report.get('overall'):
            overall = report['overall']
            try:
                self.db.record_training_run(
                    iteration=self.iteration,
                    detection_rate=float(
                        overall['detection_rate'].rstrip('%')) / 100,
                    f1_score=float(overall['f1_score']),
                    metrics=overall,
                )
            except Exception as exc:
                print(f"⚠️  PatternDB run record failed: {exc}")

        print("\n📋 Accuracy Report:")
        print(json.dumps(report['overall'], indent=2))
        print(f"Full report saved to reports/accuracy_report.json")

        return report

    def save_state(self):
        os.makedirs(_REPORTS, exist_ok=True)
        with open(os.path.join(_REPORTS, 'brain_state.json'), 'w') as f:
            json.dump({
                'iteration': self.iteration,
                'blue_patterns': self.blue.patterns,
                'red_evasions': self.red.evasions,
                'history': self.history,
                'metrics': self.metrics
            }, f, indent=2)
        # Phase 3: mirror pattern state to SQLite
        if self.db:
            try:
                self.db.save_patterns(self.blue.patterns)
            except Exception as exc:
                print(f"⚠️  PatternDB save failed: {exc}")

    def load_state(self):
        path = os.path.join(_REPORTS, 'brain_state.json')
        if os.path.exists(path):
            with open(path) as f:
                state = json.load(f)
            self.iteration = state['iteration']
            self.blue.patterns = state['blue_patterns']
            self.red.evasions = state.get('red_evasions', {})
            self.history = state['history']
            self.metrics = state['metrics']
            # Phase 3: overlay DB weights/signals onto loaded JSON state
            if self.db:
                try:
                    self.blue.patterns = self.db.load_patterns(self.blue.patterns)
                    print(f"💾 PatternDB overlay applied")
                except Exception as exc:
                    print(f"⚠️  PatternDB load failed: {exc}")
            print(f"🧠 Brain loaded — resuming at iteration {self.iteration}")
        else:
            # Phase 3: seed from DB if available (no JSON state yet)
            if self.db:
                try:
                    self.blue.patterns = self.db.load_patterns(self.blue.patterns)
                    stats = self.db.get_stats()
                    if stats['total_signals']:
                        print(f"🧠 Fresh JSON state — "
                              f"patterns seeded from PatternDB "
                              f"({stats['total_signals']} signals)")
                        return
                except Exception as exc:
                    print(f"⚠️  PatternDB seed failed: {exc}")
            print("🧠 Fresh brain — starting from iteration 0")


if __name__ == "__main__":
    # Install matplotlib if needed
    try:
        import matplotlib
    except ImportError:
        subprocess.run(['pip', 'install', 'matplotlib', 'numpy'], check=True)

    brain = ForensicBrain()
    
    brain.run(max_iterations=1500)