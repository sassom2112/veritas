# T1055 — Process Injection

## Tool sequence
1. `windows.malfind` — primary. Finds anonymous PAGE_EXECUTE_READWRITE VAD regions.
2. `windows.vadwalk --pid <PID>` — if malfind identifies a suspect PID, walk its full VAD tree.
3. `windows.dumpfiles --physaddr <addr>` — dump the shellcode region if a physical address is available.

## CONFIRMED when
- malfind returns ≥1 anonymous VAD with PAGE_EXECUTE_READWRITE and a recognizable shellcode prologue (x64: `48 83 EC`, `55 48 89 E5`; x86: `55 8B EC`).
- Any process has mapped executable anonymous pages that cannot be attributed to a loaded, signed DLL.
- vadwalk confirms VadS (private anonymous) type for the flagged region.

## REFUTED when
- malfind returns only whitelisted system regions or signed DLLs after checking all top suspect processes.
- No anonymous PAGE_EXECUTE_READWRITE regions found across MsMpEng.exe, svchost.exe, explorer.exe, lsass.exe.

## INCONCLUSIVE when
- malfind times out before completing the full scan. **Do not return CONFIRMED on a timeout.**
- Retry with `windows.malfind --pid <PID>` targeting the single most suspicious process before returning INCONCLUSIVE.

## Case context
Suspect processes for this campaign: `MsMpEng.exe` (attacker injected into Windows Defender on rocba),
`svchost.exe`, `a.exe` (httppump loader on nfury). On rocba T1055 required two rounds — Round 1 timed out
(INCONCLUSIVE), Round 2 recovered one VAD record (CONFIRMED). This is the correct behavior.
