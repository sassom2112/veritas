---
title: Architecture
nav_order: 3
permalink: /architecture
---

# Architecture

ADVERSA uses a **5-layer pipeline** pattern with a strict trust boundary at Layer 3 (the MCP Validator Gate).

<div class="mermaid">
graph TD
    subgraph L0["🧠 LAYER 0: Adversarial Simulation Core (Offline)"]
        direction TB
        DS[("mordor_dataset\nTelemetry Warehouse\n49,519 Sysmon events · 9 techniques")]
        subgraph Engine["Mutation Loop"]
            RED["Red Agent\n(msticpy_red_agent.py)"]
            ENRICH["Event Enrichment\n(msticpy_enrichment.py)\nIP · registry · process context"]
            EVOLVE["Evasion Logic\nArtifact Mutation"]
            RED <-->|Mutate Signatures| EVOLVE
            RED --> ENRICH
        end
        BLU["Blue Discriminator\n(brain.py :: BlueDiscriminator)"]
        PDB[("pattern_db.py\nSQLite Storage\nhit / miss signal weights")]
        RULES[("operational_rules.json\nHardened Rule Set\n11 rules · 3,000 iterations")]
        DS --> RED
        Engine -->|Sysmon events + enrichment| BLU
        BLU -->|record detection| PDB
        PDB -->|signal weight update| BLU
        BLU -->|export static TTP weights| RULES
    end
    subgraph L1["⚙️ LAYER 1: Orchestration & Session Execution"]
        direction LR
        SH["adversa.sh\nCLI Entry Point"]
        ORCH["investigate.py\nState Manager"]
        SH --> ORCH
    end
    RULES -->|Runtime Ingestion| ORCH
    subgraph L2["🤖 LAYER 2: Forensic Agency Tier"]
        direction TB
        subgraph AGENT_1["Phase 1 — Triage Agent  (blue_agent.py)"]
            P1["Pass 1 · Deterministic Sweep\n~25 SIFT Commands · under 60s"]
            SCORE["ASL Scoring Engine\nweighted signal match"]
            P2["Pass 2 · Agentic Loop\n75 tool-call budget"]
            P1 --> SCORE --> P2
        end
        subgraph AGENT_2["Phase 2 — Forensic Auditor  (auditor_agent.py)"]
            PAR["asyncio.gather\nIsolated MCP session per technique"]
            RND["5 rounds x 2 tools each\nCONFIRMED / REFUTED / INCONCLUSIVE"]
            ADJ["Adjusted Score\n= sum of confirmed technique weights"]
            PAR --> RND --> ADJ
        end
        AGENT_1 -->|Triage Findings Report| AGENT_2
    end
    ORCH --> AGENT_1
    API(["Anthropic API\nclaude-sonnet-4-6"])
    P2 <-->|tool_use loop| API
    RND <-->|tool_use loop| API
    subgraph L3["🛡️ LAYER 3: MCP Security Boundary  (sift_server.py)  ← ARCHITECTURAL ENFORCEMENT"]
        direction TB
        RTC["run_terminal_command\nCore Execution Primitive"]
        UTL["run_volatility\nsearch_ioc\ncompute_file_hash"]
        GATE{"Validator Gate\n1. Hard-blocked strings · 22 tokens\n2. Binary allowlist · 53 tools\n3. Quote-aware pipe split\n4. Redirect guard → reports/ only"}
        RTC --> GATE
        UTL --> GATE
    end
    P1 -->|stdio Transport| RTC
    P2 -->|stdio Transport| RTC
    RND -->|stdio Transport| RTC
    subgraph L4["🖥️ LAYER 4: Host OS & Evidence Interface"]
        direction LR
        BIN["SIFT Binaries\nvol.py · rip.pl · strings · fls · icat\nyara · md5sum · xxd · grep · find"]
        IMG[("Mounted Forensic Image\n/mnt/host\nRead-Only Target")]
        BIN --> IMG
    end
    GATE -->|Validated Native Invocation| BIN
    subgraph L5["📦 LAYER 5: Output & Campaign Management"]
        direction LR
        HTML["html_report.py\nhost-report.html"]
        JLOG[("JSONL Audit Log\nChain of Custody")]
        IOCX["extract_iocs.py\nhost-iocs.json"]
        MERGE["adversa-merge-iocs.sh\ncampaign IOC dedup"]
    end
    AGENT_2 --> HTML
    AGENT_2 --> IOCX
    GATE -.->|Atomic Append| JLOG
    IOCX -->|Accumulate threat intel| MERGE
    MERGE -.->|Dynamic IOC injection| SH
    subgraph LEGEND["Security Boundary Key"]
        direction LR
        PB["🟡 PROMPT-BASED\nOperator instructions\nAgent system prompts\nModel can ignore"]
        AB["🔴 ARCHITECTURAL\nMCP Validator Gate\nCode-enforced — model cannot override"]
    end
    classDef l0Style fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px;
    classDef l2Style fill:#e8eaf6,stroke:#3f51b5,stroke-width:2px;
    classDef l3Style fill:#ffebee,stroke:#f44336,stroke-width:3px;
    classDef l4Style fill:#e1f5fe,stroke:#03a9f4,stroke-width:2px;
    classDef l5Style fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
    classDef promptStyle fill:#fff9c4,stroke:#f9a825,stroke-width:2px;
    classDef archStyle fill:#ffebee,stroke:#c62828,stroke-width:3px;
    class L0,Engine l0Style;
    class L2,AGENT_1,AGENT_2 l2Style;
    class L3,GATE l3Style;
    class L4,BIN l4Style;
    class L5,HTML,JLOG,IOCX,MERGE l5Style;
    class PB promptStyle;
    class AB,GATE archStyle;
</div>

---

## Architectural Pattern

**Multi-agent pipeline with adversarial verification** — two Claude agents share zero session state. The Triage Agent (Optimist) proposes findings; the Forensic Auditor (Cynic) independently re-runs tool calls to verify. A CONFIRMED verdict requires a positive tool return value, not model confidence.

## Security Boundaries

| Boundary | Type | Enforcement |
|----------|------|-------------|
| Operator instructions (CLAUDE.md) | **Prompt-based** | Model can ignore; MCP layer is the real backstop |
| Agent system prompts | **Prompt-based** | Model can ignore; Auditor independence enforced by separate session |
| MCP Validator Gate (Layer 3) | **Architectural** | Code-enforced in Python before `subprocess.run()`; model cannot override |
| Binary allowlist | **Architectural** | 53 approved SIFT tools; any other binary rejected at the gate |
| Redirect guard | **Architectural** | `os.path.realpath()` checked; no writes outside `reports/` |
| Auditor independence | **Architectural** | Separate `asyncio` task, separate MCP session, no shared state with Triage Agent |

<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true, theme:'dark'});</script>
