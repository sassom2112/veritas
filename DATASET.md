---
title: Dataset
nav_order: 11
permalink: /dataset
---

# Dataset Documentation

---

## Primary: SANS FIND EVIL! 2026 Forensic Case Data

VERITAS was validated against real Windows forensic images from the SANS FIND EVIL!
Hackathon 2026 case data — APT intrusion artifacts across multiple hosts.

| Property | Value |
|----------|-------|
| Format | Windows disk images (E01/raw) + raw memory captures |
| Mount method | Read-only via SIFT Workstation (`mount -o ro`) |
| Platform | SANS SIFT Workstation (Ubuntu), SIFT forensic tool suite |
| Evidence modification | Structurally impossible — MCP Validator Gate enforces `reports/` write boundary |

### Hosts Investigated

| Host | IP | Role | Disk image | Memory capture |
|------|----|------|-----------|----------------|
| nfury | 10.3.58.6 | Victim | Windows 7 x64 | Yes |
| tdungan | 10.3.58.7 | Victim | Windows 7 x64 | Yes |
| nromanoff | 10.3.58.5 | Victim | Windows 7 x64 | Yes |
| rocba | 192.168.1.5 | C2 relay node | Windows x64 | Yes |

All images were mounted read-only. No write access to evidence at any point. The MCP
Validator Gate's write-target guard resolves all redirect targets via `os.path.realpath()`
and requires them to land inside `reports/`. Chain of custody is preserved.

### What Was Found

All findings are documented in the live investigation reports with full Auditor
argumentation transcripts:

- [nfury Investigation](/nfury) — 15 confirmed, 4 refuted
- [tdungan Investigation](/tdungan) — 13 confirmed, 4 refuted
- [nromanoff Investigation](/nromanoff) — 3 confirmed, 4 refuted
- [rocba Investigation](/rocba) — 1 confirmed, 4 refuted

Every confirmed finding traces to a specific tool call in `reports/audit_log.jsonl`.

---

## Secondary: Triage Signal Corpus

The corpus-calibrated detection layer uses log-odds weights derived from labeled
malware samples.

| Source | Purpose | Samples |
|--------|---------|---------|
| MalwareBazaar | Malware frequency estimates (p_malware) | 800+ labeled samples |
| HybridAnalysis | Behavioral metadata, string extraction | Supplements MalwareBazaar |
| SIFT tool output baseline | Benign frequency estimates (p_benign) | Curated Windows system strings |

Every weight is traceable to a source SHA-256. Weights are stored in
`data/calibrated_weights.json`. The corpus covers 9 MITRE ATT&CK techniques.

This is a proof-of-concept detection layer. The triage signals generate candidates
for the Auditor to verify. The Auditor's physical artifact requirement provides
the precision layer.

---

## Tertiary: Sysmon Adversarial Training Data

The adversarial Red/Blue training loop (`brain.py`) uses real Windows Sysmon
telemetry for signal hardening research.

| Source | Events | Techniques | Purpose |
|--------|--------|-----------|---------|
| OTRF/Mordor Security Datasets | 49,519 | 8 MITRE | Adversarial signal extraction |

**Domain gap:** Sysmon event fields (`ProcessGuid`, `CommandLine`, `ParentImage`)
are absent from static disk forensic output. These signals are validated on live
telemetry, not on mounted disk images. The deployment path for this component
is a live Sysmon endpoint.

Technical details: [Domain Gap Analysis](/docs/domain_gap_results)

---

## Reproducibility

Any investigator with access to the same mounted images can reproduce all confirmed
findings:

```bash
# From the audit log, find the confirming tool call for any technique
grep "T1055" reports/audit_log.jsonl | python3 -m json.tool

# Run the exact command on the same mounted image
# The output will match what the Auditor saw
```

The append-only audit log contains every command, every output, every timestamp.
No trust in the model is required to verify a confirmed finding.
