---
nav_exclude: true
---

# False Positive & Failure Mode Log

## FP-001: Scoring Engine Self-Match
**Date:** 2026-05-12
**Severity:** High
**Description:** 
Confidence scorer returned 100/100 on a clean SIFT workstation 
(no compromise). Agent was investigating the live system and 
read its own source code (`blue_agent.py`) via:
`cat /home/sansforensics/blue_agent.py | head -50`

The source code contained IOC pattern strings like 
`c2_ip_in_registry`, `beacon`, `masquerad` which matched 
the scoring engine's generic keyword list.

**Root Cause:** 
`parse_findings()` used generic words instead of specific 
IOC values. Combined with no exclusion of script reads from 
the scoring corpus.

**Fix Applied:**
1. Replaced generic keywords with specific IOC values
   (e.g. '12.190.135.235' instead of 'http://')
2. Added filter to exclude outputs containing 
   'ANTHROPIC_API_KEY' from scoring corpus
3. Added command exclusion for reads of blue_agent.py itself

**Lesson:**
Agents that can read their own source code will match on 
their own IOC patterns. Scoring corpus must be filtered 
to forensic tool output only.

**Verification:**
Re-ran against clean SIFT workstation after fix.
Result: 0/100 — No Strong IOCs ✅
Re-ran against nromanoff Win7 image.
Result: 100/100 — HIGH CONFIDENCE ✅