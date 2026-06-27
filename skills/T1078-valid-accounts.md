# T1078 — Valid Accounts

## Tool sequence
1. `windows.hashdump` — extract local account hashes from memory.
2. `strings /mnt/host/Windows/System32/config/SAM 2>/dev/null | grep -v 'Builtin\|SYSTEM'` — non-default accounts.
3. `grep -oa 'SRL-Helpdesk\|vibranium\|[A-Za-z0-9_-]\{8,\}' /mnt/host/Windows/System32/winevt/Logs/Security.evtx 2>/dev/null | sort -u | head -30` — account names in Security log.

## CONFIRMED when
- Attacker-created or compromised account used for authentication in Security log (Event ID 4624 logon with known-bad account).
- NTLM hash for a campaign account (SRL-Helpdesk `4c3f5e9f...`) found in hashdump.
- Credential harvester output found on disk containing account credentials.

## REFUTED when
- No non-standard accounts in SAM or Security log.
- All logon events (4624) trace to legitimate user accounts and SYSTEM.

## Case context
On nfury: `SRL-Helpdesk` confirmed via hashdump and Event ID 4720.
On tdungan: same NTLM hash `4c3f5e9f...` matched exactly — credential reuse from nfury confirmed.
On nromanoff: `vibranium` credentials extracted from memory via hashdump.
Valid Accounts is a high-value technique to confirm — it directly ties to lateral movement chain.
