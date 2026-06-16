# VERITAS — Autonomous Windows Forensic Investigation

VERITAS solves the AI forensic investigator trust problem — not by finding a better model, but by making hallucinated findings structurally unable to reach the final report.

**Three agents. Disk Agent + Memory Agent investigate on separate evidentiary layers. The Forensic Auditor** receives only the findings list and must confirm each claim from physical bytes before it enters the report. Model confidence produces neither CONFIRMED nor REFUTED.

Three hosts, real SANS case data: **32 confirmed, 16 correctly refuted.** The 4-refutal pattern holds across every host including the attacker's own C2 node — an operator who deliberately left nothing on disk. The Auditor found one thing and dismissed four. Same standard, every host.

Built for the **SANS FIND EVIL! Hackathon 2026** · Custom MCP Server + Multi-Agent Adversarial Pipeline

---

## The Problem Nobody Solved

Every tool closes the speed gap. VERITAS closes the trust gap.

Autonomous AI investigators hallucinate. Ask an LLM whether credential dumping occurred and it
will find something that looks like credential dumping — whether or not the binary is actually on
disk. Prompt instructions do not fix this. The leading platform in this space (Valhuntir) reached
the same conclusion and kept the human in the loop.

**VERITAS is the architecture that removes the human from the verification loop without losing
forensic integrity.** A finding is only CONFIRMED when a second independent agent — one that
receives the findings list and nothing else — calls a real forensic tool and reads physical bytes
off disk. Model confidence produces neither CONFIRMED nor REFUTED.

---

## Why Three Agents

This is the same architectural pattern as constraint projection in adversarial ML — you don't fix the problem by optimizing the thing that produces bad outputs, you build the layer that forces outputs back into valid space before they count. The Forensic Auditor is that layer. It doesn't care how confident the Disk Agent was. It only cares what the filesystem says.

The Disk Agent, Memory Agent, and Forensic Auditor are structurally decoupled: the Auditor receives the findings list and nothing else. No investigation context, no Phase 1 scores, no technique labels. If it can't re-derive the finding from physical bytes in an isolated MCP session, the finding doesn't ship. Wide investigation + adversarial verification is the correct architecture — not investigation alone, not verification alone.

---

## Architecture

![VERITAS Pipeline Architecture](docs/adversa-architecture.png)

**Phase 1 — Deterministic triage** (~25 SIFT commands, no LLM, <60 s)
Corpus-calibrated log-odds weights from 800+ labeled malware samples. Fully reproducible.

**Phase 1a — Disk Agent (blue_agent.py)** (75-call Claude budget)
Investigates event logs, prefetch, SAM hives, registry, network artifacts.
Receives raw artifacts only — no Phase 1 score, no technique labels. Structural decoupling.

**Phase 1b — Memory Agent (memory_agent.py)** (parallel)
Volatility 3 — process injection, VAD anomalies, credential dumps invisible on disk.

**Phase 2 — Forensic Auditor (auditor_agent.py)** (parallel, isolated MCP sessions)
Receives the findings list and nothing else. Mandate: assume every finding is false until
the filesystem proves otherwise. CONFIRMED requires a positive tool return value.
5 rounds × 3 tool calls per technique, all challenges concurrent via `asyncio.gather`.

**IOC extraction → HTML report → campaign propagation**

---

## Results

Three hosts, real SANS case data. All findings independently reproducible from audit log.

### nfury (10.3.58.6) — full pipeline

| Phase | Found | Detail |
|---|---|---|
| Deterministic sweep (< 60 s, no LLM) | 2 candidates | T1560.001 (archive extensions), T1569.002 (PsExec strings) |
| Agentic investigation (75 tool calls) | +12 candidates | backdoor, injection chain, account creation, lateral movement, persistence, exfil staging |
| Memory — Volatility 3 (parallel) | +5 candidates | process injection, credential dump, VAD anomalies |
| **Forensic Auditor** | **15 confirmed · 4 refuted** | Every confirmed finding backed by physical artifact citation |
| Runtime | 969 s (~16 min) | Cost: ~$14 |

Confirmed attack chain: httppump backdoor (`svchost.exe` in `$Recycle.Bin`, timestomped 2008,
SHA-256 `f293fdb9…`), C2 at `192.168.1.5/ads/`, loader `a.exe` (PDB: `httppump/inner/i.pdb`,
127 `PAGE_EXECUTE_READWRITE` VADs via malfind), `SRL-Helpdesk` account creation (Event ID 4720),
`psexesvc.exe` on disk (T1569.002), `system4.rar` + `chrome.7z` exfil staging.

Refuted (4): T1071.001, T1134, T1547.001, T1574 — memory-only signals, no disk corroboration.
**The refutals are the proof the architecture works.**

### tdungan (10.3.58.7) — campaign mode with nfury IOCs

| Phase | Found | Detail |
|---|---|---|
| Investigation (disk + memory) | 17 candidates | phishing initial access, credential harvester, lateral movement, persistence |
| **Forensic Auditor** | **13 confirmed · 4 refuted** | Every confirmed finding backed by physical artifact citation |
| Runtime | 880 s (~15 min) | Cost: ~$14 |

T1566 (Phishing) confirmed — campaign initial access identified. `HYDRAKATZ.EXE` in Prefetch
(Hydra + Mimikatz, purpose-built credential harvester). `SRL-Helpdesk` NTLM hash `4c3f5e9f…`
**matches nfury exactly** — credential reuse confirmed across hosts. Different httppump variant
(SHA-256 `91f16fc5…`): same C2, evolved tooling.

### nromanoff (10.3.58.5) — standalone, distinct tool family

| Phase | Found | Detail |
|---|---|---|
| Investigation (disk + memory) | 7 candidates | distinct tool family (spinlock.exe), external C2, lateral movement |
| **Forensic Auditor** | **3 confirmed · 4 refuted** | Every confirmed finding backed by physical artifact citation |
| Runtime | ~880 s (~15 min) | Cost: ~$14 |

`spinlock.exe` — PyInstaller Python backdoor, distinct from httppump. External C2 at
`199.73.28.114:443` with self-signed TLS cert (`CN=199.73.28.114`) — the only confirmed
live external C2 in the campaign. `PSEXESVC.EXE` on disk (T1569.002). `vibranium` account
credentials extracted from memory. Same refutation pattern: 4 memory-only signals with no
disk corroboration — consistent with nfury and tdungan.

### rocba (192.168.1.5) — the attacker's C2 relay node

| Phase | Found | Detail |
|---|---|---|
| Investigation (memory only) | 5 candidates | All from memory — disk score zero by design |
| **Forensic Auditor** | **1 confirmed · 4 refuted** | Every confirmed finding backed by physical artifact citation |
| Runtime | 1383 s (~23 min) | Cost: ~$14 |

Zero disk artifacts — no persistence, no lateral movement, no staged files. This host
deliberately leaves nothing on disk. The Auditor correctly found one thing and dismissed four.

T1055 confirmed in `MsMpEng.exe` (Windows Defender's engine): two `VadS PAGE_EXECUTE_READWRITE`
regions at `0x1f081330000` and `0x1f0818a0000`, x64 shellcode prologue recovered before
malfind timeout. The attacker injected into their own AV to hide C2 traffic inside a trusted
Windows process. Round 1 timed out — Auditor returned INCONCLUSIVE. Round 2 recovered one VAD
record and returned CONFIRMED. Timeout → INCONCLUSIVE, not timeout → CONFIRMED. The architecture
fails safe.

Refuted (4): T1071.001, T1134, T1547.001, T1574 — same four memory-only signals as nfury.
The Auditor applies the same physical verification standard to the attacker's own infrastructure.

**32 techniques confirmed across 48 detected. 16 correctly refuted. 4 hosts — 3 victims + the attacker's C2 node. Under $60 total.**

The 4-refutal pattern holds across every host: nfury (4), tdungan (4), nromanoff (4), rocba (4).
Same memory-only signals, consistently dismissed. Different host types, same Auditor behavior.

---

## Security Boundary

![VERITAS Security Boundary](docs/adversa-guardrails.png)

Every forensic action flows through one MCP primitive: `run_terminal_command`.
Four gates execute in Python before any subprocess call.

1. **Hard-blocked strings** — 22 tokens: `shred`, `mkfs`, `curl`, `wget`, `nc`, `sudo`,
   `$()`, backtick, `system(`, specific service control verbs. Command substitution blocked
   because an attacker-controlled log can inject a second command as an argument.
2. **53-binary SIFT allowlist** — unknown binaries rejected unconditionally. `sed` excluded —
   its `-e` flag passes the pattern space to the shell.
3. **Quote-aware pipeline parser** — tracks single-quoted substrings; `|` inside quotes is
   argument content, not a separator. Required for `grep -iE '(http|https|ftp)'`.
4. **Write-target guard** — all `>`, `>>`, `tee` targets resolved via `os.path.realpath()`.
   Must land inside `reports/`. Symlink and `../` injection fail at the math level.

`audit_log.jsonl` is appended atomically via `os.open + os.write` before every subprocess call.
Evidence modification is structurally impossible — not prompt-dependent.

---

## Quick Start

```bash
git clone https://github.com/sassom2112/find-evil-2026.git
cd find-evil-2026
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."

# Terminal 1 — MCP forensic tool server
python3 custom-agent/sift_server.py

# Terminal 2 — full investigation
python3 custom-agent/investigate.py --case /mnt/hostname

# Fast deterministic triage only — no API key, <10 s
python3 fast-triage/fast_triage.py /mnt/hostname
```

Requires a mounted Windows disk image (read-only). The framework reads via standard SIFT/Sleuth
Kit tools — no write access to evidence.

### Campaign mode — explicit IOC propagation

```bash
# Investigate first host
python3 custom-agent/investigate.py --case ~/cases/nfury

# Second host with nfury IOCs injected (explicit declaration required)
python3 custom-agent/investigate.py --case ~/cases/tdungan nfury

# Third host with all prior IOCs
python3 custom-agent/investigate.py --case ~/cases/controller nfury tdungan
```

Host names resolve to `reports/<host>-iocs.json`. Explicit declaration prevents cross-campaign
contamination — IOCs are never injected automatically.

### Rebuild signal weights

```bash
# Retrain Sysmon ASL (requires Mordor datasets — see DATASET.md)
python3 training/brain.py                  # ~30 min, 4500 iterations
python3 training/sigma_exporter.py         # → reports/sigma_rules/
```

Pre-built weights are already in `data/calibrated_weights.json`. Retraining is only needed to extend coverage beyond the 9 included MITRE techniques.

---

## Detection Signal Stack

Two independent signal sources feed Pass 1 scoring.

**Corpus-calibrated weights** (`data/calibrated_weights.json`)
Log-odds ratios from 800+ labeled samples (MalwareBazaar + HybridAnalysis):
```
log_odds = log2( (p_malware + 0.05) / (p_benign + 0.05) )
weight   = normalize(log_odds) → [0, 1]
```
Covers 9 MITRE techniques. Every weight traceable to a source SHA-256.

**Sysmon ASL operational rules** (`reports/operational_rules.json`)
Adversarially trained on 49,519 real Windows Sysmon events (OTRF Mordor).
Red Agent generates evasion variants; Blue Agent extracts discriminating field values from misses.
2,031 logged evasion attempts. Each exported Sigma rule embeds its bypass rate.

Domain gap: these rules are validated on live Sysmon telemetry. Sysmon event fields
(ProcessGuid, CommandLine, ParentImage) are absent from static disk forensic output — they
do not independently drive disk-forensic detections in the current pipeline. Connecting
this layer to a live Sysmon endpoint path is the next engineering step.

---

## Components

| File | Role |
|---|---|
| `custom-agent/investigate.py` | Orchestrator — full pipeline end to end |
| `custom-agent/blue_agent.py` | Disk Agent — Pass 1 scoring + Pass 2 agentic loop |
| `custom-agent/memory_agent.py` | Memory Agent — Volatility 3 parallel path |
| `custom-agent/auditor_agent.py` | Forensic Auditor — adversarial parallel re-verification |
| `custom-agent/sift_server.py` | MCP server — 4-gate validator, subprocess execution |
| `custom-agent/extract_iocs.py` | IOC extraction — confirmed artifacts only |
| `custom-agent/html_report.py` | HTML report — exec summary, IOC table, Auditor transcript |
| `fast-triage/fast_triage.py` | Deterministic triage — no LLM, sub-10 s |
| `training/brain.py` | Sysmon ASL training — Red/Blue adversarial loop |
| `training/sigma_exporter.py` | Exports trained signals → `reports/sigma_rules/` |

---

## Honest Limitations

**Triage precision by design, not accident.** The triage layer is a deliberately wide net
calibrated for forensic images pre-selected for analysis — not live endpoint monitoring.
On nfury: 19 triage flags reduced to 15 confirmed, 4 correctly refuted by the Auditor.
That 21% refusal rate is the architecture working as intended. Applying triage weights to
a benign endpoint outside this context produces noise — which is exactly why the Auditor
exists. Wide triage + adversarial verification is the correct two-stage architecture.

**Three hosts, one campaign.** nfury, tdungan, and rocba share an operator and C2 infrastructure.
Generalization to a novel campaign with different tooling is not yet validated.

**Sysmon ASL domain gap.** Signals learned from live event telemetry do not transfer cleanly to
static disk forensic output. Documented, not papered over.

**Volatility malfind timeouts.** On large memory images, `windows.malfind` can exceed the
120 s subprocess timeout. The Auditor falls back to direct vol invocation and marks the finding
INCONCLUSIVE if evidence cannot be recovered — it fails safe.

**$14/host, ~16 minutes.** Cheap relative to analyst time. Not free. Does not scale to 500
simultaneous endpoints without parallel infrastructure.

---

## License

MIT
