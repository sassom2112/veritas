# T1574 — Hijack Execution Flow (DLL Search Order / Side-loading)

## Tool sequence
1. `windows.dlllist` — list loaded DLLs per process. Look for DLLs loaded from non-standard paths.
2. `find /mnt/host -iname 'version.dll' -o -iname 'wtsapi32.dll' -o -iname 'cryptsp.dll' 2>/dev/null | grep -v 'System32\|SysWOW64\|WinSxS'` — DLLs outside standard paths.
3. `find /mnt/host -iname '*.dll' -newer /mnt/host/Windows/System32/kernel32.dll 2>/dev/null | head -20` — recently modified DLLs.

## CONFIRMED when
- A DLL found in a non-standard path (Temp, AppData, attacker directory) that shares the name of a legitimate System32 DLL.
- dlllist shows a process loading a DLL from a user-writable path where it should not be loading from.
- DLL timestamp matches attacker activity window.

## REFUTED when
- No DLLs found outside System32/SysWOW64/WinSxS after full image search.
- All loaded DLLs in dlllist trace to expected system paths or signed application directories.
- **Expected result for this campaign:** T1574 is refuted on all four hosts. Volatility DLL
  analysis produces output for any running process — the signal is noise without a DLL in
  a non-standard location.

## Case context
T1574 is refuted on all campaign hosts. The Memory Agent flags it from DLL load analysis.
Look specifically for user-writable path DLLs — the absence of such artifacts is the refutation.
