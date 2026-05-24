#!/usr/bin/env python3
"""
forensic_brain.py — ASL training loop for the disk forensic artifact domain.

Retrains the ADVERSA detection model on SIFT-format disk artifacts
(strings output, fls listings, rip.pl registry dumps) rather than
Sysmon event logs.  Produces forensic_brain_state.json and then
calls export_patterns.py --disk-state to merge into operational_rules.json.

Usage:
    python3 custom-agent/forensic_brain.py                  # 500 iterations
    python3 custom-agent/forensic_brain.py --iterations 200 # quick test
    python3 custom-agent/forensic_brain.py --export-only    # export without training
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone

_HERE         = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, '..'))
_REPORTS      = os.path.join(_PROJECT_ROOT, 'reports')
_STATE_FILE   = os.path.join(_REPORTS, 'forensic_brain_state.json')

sys.path.insert(0, _HERE)
from forensic_red_agent import ForensicRedAgent


def _api_retry(fn, max_retries=4, base_delay=10):
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as e:
            if ('529' in str(e) or 'overloaded' in str(e).lower()) and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 3)
                print(f'   ⏳ API overloaded — retry {attempt+1}/{max_retries-1} in {delay:.1f}s')
                time.sleep(delay)
            else:
                raise
    return None


# ---------------------------------------------------------------------------
# Initial Blue Agent signal set — disk-domain strings / paths only.
# Deliberately sparse: the ASL loop adds new signals via learn().
# ---------------------------------------------------------------------------
_INITIAL_PATTERNS: dict[str, dict] = {
    'T1003.001': {
        'name': 'Credential Dumping (LSASS)',
        'signals': ['mimikatz', 'sekurlsa', 'lsass.dmp', 'procdump', 'comsvcs.dll'],
        'weight': 35,
    },
    'T1547.001': {
        'name': 'Registry Run Key',
        'signals': ['currentversion\\run', 'currentversion\\runonce', 'dllhost\\svchost'],
        'weight': 35,
    },
    'T1569.002': {
        'name': 'PsExec',
        'signals': ['psexesvc', 'psexec', '\\\\admin$', 'remcomsvc'],
        'weight': 35,
    },
    'T1036.005': {
        'name': 'Binary Masquerading',
        'signals': ['102400', 'dllhost\\svchost.exe', 'upx', 'wrong imports'],
        'weight': 35,
    },
    'T1087.001': {
        'name': 'Account Discovery',
        'signals': ['seatbelt', 'sharpview', 'enumdomainusers', 'getdomaingroup', 'bloodhound'],
        'weight': 35,
    },
    'T1059.001': {
        'name': 'PowerShell Execution',
        'signals': ['invoke-expression', 'frombase64string', 'powershell -enc', 'iex'],
        'weight': 35,
    },
    'T1548.002': {
        'name': 'UAC Bypass',
        'signals': ['fodhelper', 'sdclt', 'ms-settings\\shell\\open', 'eventvwr'],
        'weight': 35,
    },
    'T1560.001': {
        'name': 'Data Archival',
        'signals': ['winrar', 'rar.exe', '7za.exe', '.rar', '.7z'],
        'weight': 35,
    },
}

# Signals that survive pruning regardless of recent firing rate.
# These are technique-invariant disk artifacts with no benign overlap.
_PROTECTED = frozenset({
    'mimikatz', 'sekurlsa', 'psexesvc', 'remcomsvc', 'dllhost\\svchost',
    'enumdomainusers', 'fodhelper', 'frombase64string',
})

import re as _re


class ForensicBlueAgent:
    """
    Discriminator for disk forensic artifacts.

    Scoring: 2+ signal hits → full weight; 1 protected signal → half weight;
    1 generic signal → 0.  Same logic as brain.py BlueAgent.
    """

    def __init__(self):
        self.patterns = {
            tid: dict(data) for tid, data in _INITIAL_PATTERNS.items()
        }

    def discriminate(self, artifact: str):
        """
        Returns (score, matched_dict, reasons).
        artifact is a multi-line SIFT-format string.
        """
        text = artifact.lower().replace('\\\\', '\\')

        if 'anthropic_api_key' in text:
            return 0, {}, []

        total = 0
        matched = {}
        reasons = []

        for tid, data in self.patterns.items():
            hits = [
                s for s in data['signals']
                if s.lower().replace('\\\\', '\\') in text
            ]
            if not hits:
                continue

            if len(hits) >= 2:
                w = data['weight']
            elif hits[0].lower().replace('\\\\', '\\') in _PROTECTED:
                w = data['weight'] // 2
            else:
                w = 0

            if w > 0:
                total += w
                matched[tid] = hits
                reasons.append(f"{data['name']} (+{w}) via {hits}")

        return total, matched, reasons

    def learn(self, tid: str, artifact: str, raw_event: str = None):
        """
        Discriminator learns a new signal after missing an attack.
        raw_event is the full SIFT artifact string (not a Sysmon dict).
        """
        import anthropic

        context = (
            f'Missed SIFT artifact:\n{(raw_event or artifact)[:600]}\n\n'
            'Extract ONE specific string that reliably identifies this technique '
            'in SIFT disk forensic output (strings command, fls listing, or registry dump). '
            'The string MUST appear verbatim in the artifact above.'
        )

        client = anthropic.Anthropic()
        try:
            resp = _api_retry(lambda: client.messages.create(
                model='claude-haiku-4-5-20251001',
                max_tokens=150,
                messages=[{
                    'role': 'user',
                    'content': (
                        f'You are a disk forensic analyst.\n'
                        f'Attack NOT detected: {tid}\n'
                        f'Current signals: {self.patterns[tid]["signals"]}\n\n'
                        f'{context}\n\n'
                        f'Respond in JSON only, no markdown:\n'
                        f'{{"new_signal": "exact_string_to_search_for"}}'
                    ),
                }],
            ))

            raw   = resp.content[0].text.strip()
            start = raw.find('{')
            end   = raw.rfind('}') + 1
            if start == -1 or end <= start:
                raise ValueError(f'no JSON: {raw[:60]!r}')
            sig = json.loads(raw[start:end])['new_signal'].strip()

            if (not sig
                    or ' AND ' in sig.upper()
                    or ' OR '  in sig.upper()
                    or '.*' in sig
                    or _re.match(r'^T\d{4}', sig)
                    or sig in self.patterns[tid]['signals']):
                print(f'   ⚠️  Rejected: {sig[:50]!r}')
                return None

            self.patterns[tid]['signals'].append(sig)
            print(f'   🔵 Learned [{tid}]: {sig!r}')
            return sig

        except Exception as e:
            print(f'   ⚠️  Blue learn failed: {e}')
            return None

    def tune_weights(self, history: list):
        """Weight tuning + signal pruning based on recent performance."""
        for tid in self.patterns:
            recent = [h for h in history[-10:] if h['technique'] == tid]
            if len(recent) < 2:
                continue

            hit_rate = sum(1 for r in recent if r['detected']) / len(recent)
            old_w    = self.patterns[tid]['weight']
            if hit_rate > 0.8:
                self.patterns[tid]['weight'] = min(old_w + 5, 50)
            elif hit_rate < 0.3:
                self.patterns[tid]['weight'] = max(old_w - 5, 28)

            # Prune only after enough observations
            tech_hist = [h for h in history if h['technique'] == tid]
            if len(tech_hist) < 15:
                continue
            recent_texts = [h['artifact'].lower() for h in tech_hist[-50:]]
            active = []
            for sig in self.patterns[tid]['signals']:
                sig_low   = sig.lower().replace('\\\\', '\\')
                fired     = any(sig_low in t for t in recent_texts)
                protected = sig_low in _PROTECTED
                if fired or protected:
                    active.append(sig)
                else:
                    print(f'   ✂️  Pruned [{tid}]: {sig!r}')
            if active:
                self.patterns[tid]['signals'] = active


class ForensicBrain:
    """
    ASL training loop for the disk forensic artifact domain.

    Red Agent generates SIFT-format attack artifacts.
    Blue Agent learns to detect them via string matching + weight tuning.
    Independent state from brain.py — does not touch brain_state.json.
    """

    def __init__(self):
        self.red       = ForensicRedAgent()
        self.blue      = ForensicBlueAgent()
        self.history:  list  = []
        self.iteration: int  = 0
        self.metrics: dict   = {
            'iterations':          [],
            'blue_scores':         [],
            'detection_flags':     [],
            'red_generations':     [],
            'blue_pattern_counts': [],
            'weights':             {t: [] for t in self.blue.patterns},
        }

    def run(self, max_iterations: int = 500):
        print(f"\n{'═'*60}")
        print(f'  FORENSIC ASL TRAINING — {max_iterations} iterations')
        print(f'  Domain: disk forensic artifacts (SIFT format)')
        print(f"{'═'*60}")

        self._load_state()

        for _ in range(max_iterations):
            self.iteration += 1
            print(f'\n── Iter {self.iteration}/{max_iterations} ──')

            # ── RED: generate SIFT artifact ──────────────────────
            tid, artifact = self.red.next_technique()
            print(f'🔴 {tid}: {artifact[:80].split(chr(10))[0]}...')

            # ── BLUE: discriminate ───────────────────────────────
            score, matched, reasons = self.blue.discriminate(artifact)
            detected = score >= 40
            print(f'🔵 score={score} {"✅ DETECTED" if detected else "❌ MISSED"}')

            record = {
                'iteration': self.iteration,
                'technique': tid,
                'artifact':  artifact,
                'score':     score,
                'detected':  detected,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            self.history.append(record)

            # ── METRICS ─────────────────────────────────────────
            self.metrics['iterations'].append(self.iteration)
            self.metrics['blue_scores'].append(score)
            self.metrics['detection_flags'].append(1 if detected else 0)
            self.metrics['red_generations'].append(
                len(self.red.evasions.get(tid, []))
            )
            self.metrics['blue_pattern_counts'].append(
                sum(len(d['signals']) for d in self.blue.patterns.values())
            )
            for t, d in self.blue.patterns.items():
                self.metrics['weights'][t].append(d['weight'])

            # ── ADVERSARIAL LEARNING ────────────────────────────
            if tid == 'BENIGN':
                if detected:
                    print('   ⚠️  False positive — penalizing firing signals')
                    for ftid, sigs in matched.items():
                        for sig in sigs:
                            if sig.lower() not in _PROTECTED:
                                old = self.blue.patterns[ftid]['weight']
                                self.blue.patterns[ftid]['weight'] = max(old - 3, 28)
            elif detected:
                caught = [s for sigs in matched.values() for s in sigs]
                self.red.evolve(tid, caught)
            else:
                self.blue.learn(tid, artifact, self.red.last_raw_event)

            if self.iteration % 5 == 0:
                self.blue.tune_weights(self.history)
                self._scoreboard()

            self._save_state()

        print(f"\n{'═'*60}")
        print(f'  FORENSIC TRAINING COMPLETE — {max_iterations} iterations')
        print(f"{'═'*60}")
        self._scoreboard()
        self._plot()
        self._accuracy_report()

    def _scoreboard(self):
        recent    = self.history[-20:] if len(self.history) >= 20 else self.history
        det_rate  = sum(1 for r in recent if r['detected']) / len(recent)
        n_signals = sum(len(d['signals']) for d in self.blue.patterns.values())
        print(f'\n📊 Scoreboard (last {len(recent)}): '
              f'detection={det_rate:.0%}  patterns={n_signals}')
        for tid, d in self.blue.patterns.items():
            rt = [r for r in recent if r['technique'] == tid]
            if rt:
                r = sum(1 for x in rt if x['detected']) / len(rt)
                print(f'   {tid}: {r:.0%} det  w={d["weight"]}  signals={len(d["signals"])}')

    def _plot(self):
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError:
            print('⚠️  matplotlib not available — skipping graphs')
            return

        iters = self.metrics['iterations']
        if len(iters) < 2:
            return

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Forensic ASL Training — Disk Domain', fontsize=16, fontweight='bold')

        # Detection score
        ax = axes[0, 0]
        ax.plot(iters, self.metrics['blue_scores'], color='#2196F3', alpha=0.4, linewidth=1)
        w = min(10, len(iters))
        rolling = np.convolve(self.metrics['blue_scores'], np.ones(w) / w, mode='valid')
        ax.plot(iters[w-1:], rolling, color='#1565C0', linewidth=2.5, label=f'{w}-iter avg')
        ax.axhline(40, color='orange', linestyle='--', linewidth=1.5, label='Threshold')
        ax.axhline(70, color='red',    linestyle='--', linewidth=1.5, label='HIGH')
        ax.set_title('Blue Score Over Time', fontweight='bold')
        ax.legend(fontsize=8)
        ax.set_ylim(0, 110)

        # Detection rate
        ax = axes[0, 1]
        flags = self.metrics['detection_flags']
        win   = min(10, len(flags))
        rate  = [sum(flags[max(0, i-win):i+1]) / min(i+1, win) for i in range(len(flags))]
        ax.plot(iters, rate, color='#4CAF50', linewidth=2.5)
        ax.fill_between(iters, rate, alpha=0.2, color='#4CAF50')
        ax.axhline(0.5, color='gray', linestyle='--', linewidth=1)
        ax.set_title('Detection Rate', fontweight='bold')
        ax.set_ylim(-0.1, 1.1)

        # Red evasions vs Blue patterns
        ax    = axes[1, 0]
        ax2   = ax.twinx()
        l1, = ax.plot(iters, self.metrics['red_generations'],  color='#f44336', linewidth=2.5, label='Red evasions')
        l2, = ax2.plot(iters, self.metrics['blue_pattern_counts'], color='#2196F3', linewidth=2.5, linestyle='--', label='Blue patterns')
        ax.set_title('ASL Arms Race', fontweight='bold')
        ax.legend(handles=[l1, l2], fontsize=8, loc='upper left')

        # Weight evolution
        ax = axes[1, 1]
        palette = ['#E91E63','#9C27B0','#FF9800','#009688','#795548','#2196F3','#FF5722','#607D8B']
        for (tid, weights), color in zip(self.metrics['weights'].items(), palette):
            if weights:
                ax.plot(iters[:len(weights)], weights, label=tid, color=color,
                        linewidth=2, marker='o', markersize=3, markevery=5)
        ax.set_title('Weight Evolution Per Technique', fontweight='bold')
        ax.legend(fontsize=7, loc='upper right')
        ax.set_ylim(0, 60)

        plt.tight_layout()
        os.makedirs(_REPORTS, exist_ok=True)
        path = os.path.join(_REPORTS, 'forensic_training_graphs.png')
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f'\n📊 Graphs saved: {path}')

    def _accuracy_report(self) -> dict:
        if not self.history:
            return {}

        report = {
            'generated':       datetime.now(timezone.utc).isoformat(),
            'domain':          'disk_forensic',
            'total_iterations': self.iteration,
            'techniques':      {},
            'overall':         {},
        }
        total_hits = total_tests = 0

        for tid, data in self.blue.patterns.items():
            tests = [r for r in self.history if r['technique'] == tid]
            if not tests:
                continue
            hits   = sum(1 for r in tests if r['detected'])
            total_hits  += hits
            total_tests += len(tests)
            report['techniques'][tid] = {
                'name':              data['name'],
                'detection_rate':    f'{hits/len(tests):.0%}',
                'hits':              hits,
                'misses':            len(tests) - hits,
                'final_weight':      data['weight'],
                'patterns_learned':  len(data['signals']),
                'red_evasions':      len(self.red.evasions.get(tid, [])),
            }

        benign_fp = sum(1 for r in self.history
                        if r['technique'] == 'BENIGN' and r['detected'])
        if total_tests:
            prec = total_hits / (total_hits + benign_fp) if (total_hits + benign_fp) else 0
            rec  = total_hits / total_tests
            f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
            report['overall'] = {
                'detection_rate': f'{total_hits/total_tests:.0%}',
                'total_tests':    total_tests,
                'detections':     total_hits,
                'false_positives': benign_fp,
                'precision':      f'{prec:.0%}',
                'recall':         f'{rec:.0%}',
                'f1_score':       f'{f1:.2f}',
            }

        os.makedirs(_REPORTS, exist_ok=True)
        path = os.path.join(_REPORTS, 'forensic_accuracy_report.json')
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)
        print('\n📋 Forensic Accuracy Report:')
        print(json.dumps(report.get('overall', {}), indent=2))
        print(f'Full report: {path}')
        return report

    def _save_state(self):
        os.makedirs(_REPORTS, exist_ok=True)
        with open(_STATE_FILE, 'w') as f:
            json.dump({
                'iteration':     self.iteration,
                'domain':        'disk_forensic',
                'blue_patterns': self.blue.patterns,
                'red_evasions':  self.red.evasions,
                'history':       self.history,
                'metrics':       self.metrics,
            }, f, indent=2)

    def _load_state(self):
        if not os.path.exists(_STATE_FILE):
            print('🧠 Fresh forensic brain — starting from iteration 0')
            return
        with open(_STATE_FILE) as f:
            state = json.load(f)
        self.iteration        = state.get('iteration', 0)
        self.blue.patterns    = state.get('blue_patterns', self.blue.patterns)
        self.red.evasions     = state.get('red_evasions', {})
        self.history          = state.get('history', [])
        self.metrics          = state.get('metrics', self.metrics)
        # Ensure metrics.weights has keys for any new techniques
        for tid in self.blue.patterns:
            if tid not in self.metrics['weights']:
                self.metrics['weights'][tid] = []
        print(f'🧠 Forensic brain loaded — resuming at iteration {self.iteration}')


def main():
    parser = argparse.ArgumentParser(
        description='Forensic-domain ASL training loop'
    )
    parser.add_argument('--iterations', type=int, default=500,
                        help='Training iterations (default: 500)')
    parser.add_argument('--export-only', action='store_true',
                        help='Export current state without training')
    args = parser.parse_args()

    if args.export_only:
        if not os.path.exists(_STATE_FILE):
            print(f'ERROR: {_STATE_FILE} not found — run training first')
            sys.exit(1)
        _export()
        return

    brain = ForensicBrain()
    brain.run(max_iterations=args.iterations)
    _export()


def _export():
    """Merge disk-domain patterns into operational_rules.json."""
    export_script = os.path.join(_HERE, 'export_patterns.py')
    import subprocess
    result = subprocess.run(
        [sys.executable, export_script,
         '--disk-state', _STATE_FILE,
         '--no-sigma'],
        check=False,
    )
    if result.returncode != 0:
        print('⚠️  export_patterns.py failed — run it manually:')
        print(f'   python3 custom-agent/export_patterns.py --disk-state {_STATE_FILE}')


if __name__ == '__main__':
    main()
