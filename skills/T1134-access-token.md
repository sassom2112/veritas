# T1134 — Access Token Manipulation

## Tool sequence
1. `windows.privileges` — list process privileges. Look for SeDebugPrivilege in non-admin processes.
2. `windows.cmdline` — check for token manipulation utilities in command lines.
3. `find /mnt/host -iname 'token*.exe' -o -iname 'incognito*' 2>/dev/null` — token manipulation tools on disk.

## CONFIRMED when
- Non-system process holds SeDebugPrivilege or SeImpersonatePrivilege unexpectedly.
- Token manipulation binary (incognito, juicy-potato, printspoofer) found on disk or in Prefetch.
- windows.cmdline shows `runas` or token API calls in attacker-controlled process.

## REFUTED when
- No unusual privilege assignments in windows.privileges output.
- No token manipulation tools in disk search or Prefetch.
- SeDebugPrivilege found only in SYSTEM-level processes (expected, benign).
- **Expected result for this campaign:** T1134 is refuted on all four hosts. Memory analysis
  surfaces privilege information from any Windows process — the signal is noise without
  corroborating disk artifacts showing attacker-controlled token manipulation.

## Case context
T1134 is refuted on every campaign host (nfury, tdungan, nromanoff, rocba). The Memory Agent
flags it because privilege information is always present in Windows memory. The Auditor must
find a disk artifact proving deliberate manipulation — absence of such an artifact is refutation.
