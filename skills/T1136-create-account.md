# T1136 — Create Account

## Tool sequence
1. `find /mnt/host -iname 'Security.evtx' 2>/dev/null` — locate Security event log.
2. `grep -oa 'SRL-Helpdesk\|vibranium\|[A-Z][a-z]*-[A-Z][a-z]*' /mnt/host/Windows/System32/winevt/Logs/Security.evtx 2>/dev/null | sort -u` — scan for account names.
3. `strings /mnt/host/Windows/System32/config/SAM 2>/dev/null | grep -v 'Builtin\|Administrator\|Guest\|SYSTEM'` — non-default accounts in SAM.

## Confirm via Event ID
- Event ID 4720: User account created.
- Event ID 4728: Member added to security-enabled global group.
- Event ID 4732: Member added to security-enabled local group.

## CONFIRMED when
- A non-default account name (SRL-Helpdesk, vibranium, or campaign-specific name) found in SAM or Security log.
- Event ID 4720 entry for the account with a suspicious creation timestamp (outside business hours, during attack window).

## REFUTED when
- No non-default accounts in SAM beyond standard Windows accounts.
- Security log contains no 4720 events for unknown account names.

## Case context
`SRL-Helpdesk` account was confirmed on nfury via Event ID 4720. `vibranium` credentials were
extracted from nromanoff memory. Account creation is a key lateral movement enabler in this campaign.
