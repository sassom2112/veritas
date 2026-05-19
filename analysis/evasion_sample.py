"""
evasion_sample.py — Forensic read of brain_state.json.corrupted

Produces a verifiable random sample showing Red Agent signature mutation:
  - Before: artifact that Blue Agent detected (score >= 40)
  - Caught by: specific signals that fired
  - After: Claude-generated evolved artifact
  - Outcome: whether the evolved artifact evaded detection

Evidence for the paper's "2,031 adversarial evasions generated" claim.
Reads brain_state.json.corrupted only — no training state modified.
"""
import json
import os
import random
import textwrap
from datetime import datetime, timezone

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
_STATE = os.path.join(_ROOT, 'reports', 'brain_state.json.corrupted')
_OUT   = os.path.join(_ROOT, 'analysis', 'evasion_sample.md')

SAMPLE_N = 5
random.seed(42)  # reproducible sample

# ── Load corrupted state ──────────────────────────────────────────────────────
print(f"Loading {_STATE} ...")
with open(_STATE) as f:
    state = json.load(f)

history      = state['history']
red_evasions = state.get('red_evasions', {})

print(f"  iterations : {state['iteration']}")
print(f"  history    : {len(history)} records")
total_evasions = sum(len(v) for v in red_evasions.values())
print(f"  evasions   : {total_evasions} total across {len(red_evasions)} techniques")

# ── Build detection events index ──────────────────────────────────────────────
# For each technique, collect (iteration_index, record) where detected=True
detected_by_tech = {}
for idx, rec in enumerate(history):
    if rec['detected'] and rec['technique'] != 'BENIGN':
        tid = rec['technique']
        detected_by_tech.setdefault(tid, []).append((idx, rec))

# ── Build evasion chains ──────────────────────────────────────────────────────
# For each technique that has both detections and evasions:
#   find a detection event, find the next occurrence of that technique,
#   check if the artifact changed (evolution applied)
chains = []

for tid, evasion_list in red_evasions.items():
    if not evasion_list:
        continue
    detections = detected_by_tech.get(tid, [])
    if not detections:
        continue

    for det_idx, det_rec in detections:
        # Find next occurrence of this technique in history after the detection
        for next_idx in range(det_idx + 1, min(det_idx + 20, len(history))):
            next_rec = history[next_idx]
            if next_rec['technique'] != tid:
                continue
            if next_rec['artifact'] == det_rec['artifact']:
                continue  # same artifact, no evolution yet

            # Found an evolved artifact
            chains.append({
                'technique_id': tid,
                'detection_iter': det_rec['iteration'],
                'detection_artifact': det_rec['artifact'],
                'detection_score': det_rec['score'],
                'evolved_iter': next_rec['iteration'],
                'evolved_artifact': next_rec['artifact'],
                'evolved_score': next_rec['score'],
                'evaded': not next_rec['detected'],
                'evasion_note': evasion_list[0].get('evasion', ''),
            })
            break

print(f"\n  traceable chains : {len(chains)}")

# ── Sample ────────────────────────────────────────────────────────────────────
sample = random.sample(chains, min(SAMPLE_N, len(chains)))
# Sort by technique for readable output
sample.sort(key=lambda c: c['technique_id'])

# ── Write markdown report ─────────────────────────────────────────────────────
lines = []
lines.append("# Evasion Sample — Red Agent Signature Mutation Evidence")
lines.append(f"\n**Source:** `reports/brain_state.json.corrupted`  ")
lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ")
lines.append(f"**Total evasion variants in state:** {total_evasions}  ")
lines.append(f"**Traceable before/after chains:** {len(chains)}  ")
lines.append(f"**Sample size:** {len(sample)} (random seed=42, reproducible)  ")

lines.append("""
## Methodology

For each sample:
1. Locate a detection event (Blue score ≥ 40) in the training history.
2. Find the next occurrence of the same technique where the artifact string changed.
3. Record the evolved artifact and its detection outcome.
4. Cross-reference the `red_evasions` entry for that technique.

All values are literal strings from `history[].artifact` in the state file.
No inference or reconstruction — direct read of training telemetry.
""")

bypassed = sum(1 for c in sample if c['evaded'])
lines.append(f"**Sample bypass rate:** {bypassed}/{len(sample)} evolved artifacts evaded detection\n")
lines.append("---\n")

for i, c in enumerate(sample, 1):
    tid = c['technique_id']
    lines.append(f"## Sample {i} — {tid}")
    lines.append("")

    lines.append(f"**Iteration {c['detection_iter']} — CAUGHT** (score {c['detection_score']})")
    lines.append("```")
    lines.append(textwrap.fill(c['detection_artifact'], width=90))
    lines.append("```")
    lines.append("")

    outcome = "EVADED ✓" if c['evaded'] else "CAUGHT AGAIN ✗"
    lines.append(f"**Iteration {c['evolved_iter']} — {outcome}** (score {c['evolved_score']})")
    lines.append("```")
    lines.append(textwrap.fill(c['evolved_artifact'], width=90))
    lines.append("```")
    lines.append("")

    if c['evasion_note']:
        lines.append(f"**Claude evasion note:** {c['evasion_note']}")
        lines.append("")

    # Artifact delta — what strings appear in before but not after
    before_tokens = set(c['detection_artifact'].lower().split())
    after_tokens  = set(c['evolved_artifact'].lower().split())
    removed = before_tokens - after_tokens
    added   = after_tokens - before_tokens
    if removed:
        lines.append(f"**Tokens removed:** `{'`, `'.join(sorted(removed)[:8])}`")
    if added:
        lines.append(f"**Tokens added:** `{'`, `'.join(sorted(added)[:8])}`")
    lines.append("")
    lines.append("---\n")

# ── Technique evasion summary table ──────────────────────────────────────────
lines.append("## Evasion Count by Technique\n")
lines.append("| Technique | Name | Evasions Generated | Chains Found |")
lines.append("|-----------|------|--------------------|--------------|")
for tid, evasion_list in sorted(red_evasions.items()):
    chain_count = sum(1 for c in chains if c['technique_id'] == tid)
    # Get technique name from history
    name = next((r['technique'] for r in history if r['technique'] == tid), tid)
    # Look up name from blue_patterns
    bp = state.get('blue_patterns', {})
    tech_name = bp.get(tid, {}).get('name', tid)
    lines.append(f"| {tid} | {tech_name} | {len(evasion_list)} | {chain_count} |")

lines.append(f"\n**Total:** {total_evasions} evasion variants generated across "
             f"{len(red_evasions)} techniques during {state['iteration']} training iterations.")

report = "\n".join(lines)
with open(_OUT, 'w') as f:
    f.write(report)

print(f"\nReport written to {_OUT}")
print(f"\nSample preview:")
for c in sample:
    outcome = "EVADED" if c['evaded'] else "CAUGHT AGAIN"
    print(f"  {c['technique_id']}  iter {c['detection_iter']}→{c['evolved_iter']}  {outcome}  "
          f"score {c['detection_score']}→{c['evolved_score']}")
