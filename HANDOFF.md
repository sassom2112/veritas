# Handoff — future/cross-layer-verification (2026-06-14)

## Current task
Pre-sprint hardening before implementing Phase 2 (same-layer blind replication) in
`custom-agent/` on the `future/cross-layer-verification` branch. Three gates must
pass before writing new verification code: (1) fix JSON parse fragility in
`disk_agent.py`, (2) set Phase 2 budget caps, (3) this handoff.

## What's been tried

- **Cross-layer-only verification (`cross_verifier.py`)** — built and committed in
  `1baf74b`, but identified as architecturally wrong as the *primary* gate. It routes
  disk claims to a memory verifier and memory claims to a disk verifier. This gives a
  *different view*, not *independence*. Independence comes from a fresh agent session
  with no access to the first agent's reasoning chain, regardless of which layer's tools
  it uses. Accepted as Phase 3 (bonus cross-layer corroboration). Rejected as Phase 2.

- **Same-layer blind replication** — identified as the correct primary gate. A fresh
  disk session receives a disk `LayerClaim` (technique_id + tool_output + artifact_hint,
  no reasoning) and independently re-runs disk tools to confirm or deny. A fresh memory
  session does the same for memory claims. Not yet implemented — this is the sprint target.

- **JSON synthesis in `disk_agent.py._parse_claims()`** — current implementation asks
  for a JSON array in a final text turn, then tries `json.loads()` with a regex fallback.
  Fragile: the LLM occasionally wraps the array in prose or markdown fences that defeat
  the regex. Accepted as a known bug. Fix: replace the text-synthesis turn with a forced
  `tool_use` turn using `tool_choice={"type": "any"}` and a `record_finding` tool schema
  defined inline in `disk_agent.py` (not in `sift_server.py` — it's a reporting tool,
  not a forensic tool). Same fix needs to be applied to `memory_agent.investigate_layered()`.

## Exact next step

**Step 1 — Fix JSON fragility in `disk_agent.py` and `memory_agent.py`:**

In `disk_agent.DiskAgent._synthesis_turn()` (currently the block that appends
`_SYNTHESIS_PROMPT` to messages and calls `client.messages.create` with `tools=[]`):
Replace `tools=[]` with a `record_finding` tool definition:

```python
_RECORD_FINDING_TOOL = {
    "name": "record_finding",
    "description": "Record a confirmed technique finding with its physical evidence.",
    "input_schema": {
        "type": "object",
        "properties": {
            "technique_id":   {"type": "string", "description": "MITRE ATT&CK ID, e.g. T1569.002"},
            "technique_name": {"type": "string"},
            "tool_name":      {"type": "string", "description": "The tool that produced the evidence"},
            "tool_output":    {"type": "string", "description": "Exact tool output — not a paraphrase"},
            "artifact_hint":  {"type": "string", "description": "One-line pointer for the verifier"},
        },
        "required": ["technique_id", "technique_name", "tool_name", "tool_output", "artifact_hint"],
    },
}
```

Pass `tools=[_RECORD_FINDING_TOOL]` and `tool_choice={"type": "any"}` in the synthesis
call. Collect tool_use blocks from the response; each is one `LayerClaim`. The model
cannot return prose — it must call the tool. Apply identical fix to
`memory_agent.investigate_layered()`.

**Step 2 — Set budget caps before implementing Phase 2:**

In `disk_agent.py`: `MAX_ROUNDS=5, TOOLS_PER_ROUND=3` (15 calls) — keep as-is.
In `memory_agent.investigate_layered()`: `MAX_CALLS=20` — keep as-is.
Phase 2 verifier (to be built in `verifier.py`): `MAX_VERIFY_ROUNDS=2, TOOLS_PER_VERIFY=2`
(4 calls per claim). With ~10 claims per host: 40 calls. This is the hard cap.
Phase 3 cross-layer (existing `cross_verifier.py`, renamed): runs only on Phase 2
CONFIRMED claims. Same 4-call cap per claim.
Target: Phase 1 + Phase 2 + Phase 3 ≤ 100 total tool calls per host, ≤ $20.

**Step 3 — Build `verifier.py` with `verify_same_layer()`:**

New file `custom-agent/verifier.py`. One class `Verifier`, one public method:

```python
async def verify_same_layer(
    claims: list[LayerClaim],
    target_path: str,
    memory_path: str | None,
) -> list[SameLayerVerdict]:
```

For each claim, spawn `sift_server.py` with `VERITAS_LAYER=claim['source_layer']`
(same layer as the claim). The agent receives `technique_id`, `technique_name`,
`tool_output`, `artifact_hint` — nothing else. Must run its own tool calls and return
`CONFIRMED | REFUTED | INCONCLUSIVE`. All verifications run concurrently via
`asyncio.gather`. Add `SameLayerVerdict` TypedDict to `contracts.py`.

**Step 4 — Update `investigate.py run_cross_layer()`:**

Wire Phase 2 before Phase 3:
```
disk_claims, memory_claims = await Phase 1 (parallel)
same_layer_verdicts = await verifier.verify_same_layer(disk_claims + memory_claims, ...)
confirmed_claims = [c for c, v in zip(...) if v['verdict'] == 'CONFIRMED']
cross_verdicts = await cross_verifier.verify_cross_layer(confirmed_claims, ...)  # optional
results = adjudicate(same_layer_verdicts, cross_verdicts)
```

**Step 5 — Update `contracts.py`:**

Add `SameLayerVerdict`:
```python
class SameLayerVerdict(TypedDict):
    technique_id: str
    source_layer: str       # "disk" | "memory"
    verdict: str            # "CONFIRMED" | "REFUTED" | "INCONCLUSIVE"
    citation: str | None    # what the verifier found
```

Update `FinalTechniqueResult.final` to be driven by `SameLayerVerdict.verdict` first,
then annotated by `CrossVerdict.verdict`. Current code drives `final` from cross-verdict
directly — this is wrong.

## Open questions / blockers

- **`record_finding` tool placement**: Defined inline in `disk_agent.py` and
  `memory_agent.py` as a local constant. NOT in `sift_server.py` — it's a reporting
  primitive, not a forensic tool. The synthesis turn does not connect to the MCP server
  (uses `tools=[]` currently). Inline definition is correct.

- **Phase 3 opt-in vs. always-run**: Currently `run_cross_layer()` runs cross-layer
  verification unconditionally. Should Phase 3 be a `--corroborate` flag to control cost?
  Not decided. Default to always-run for now, add flag if cost proves excessive in testing.

- **`cross_verifier.py` rename**: Should be renamed `cross_layer.py` or folded into
  `verifier.py` as a second method. The class name `CrossVerifier` is accurate; the
  filename is the ambiguity. Defer rename until after `verifier.py` is built to avoid
  confusion during the sprint.

- **`adjudicate()` in `cross_verifier.py`**: Currently takes `(disk_claims,
  memory_claims, disk_verdicts, memory_verdicts)` — four arguments. After the sprint
  it takes `(same_layer_verdicts, cross_verdicts)` — two arguments. The function
  signature must change. The current implementation will be replaced.

## Relevant context

- **The through-line**: Same-layer blind replication in VERITAS is structurally identical
  to the constraint inflation argument in the CATT-CCS 2027 paper. "The verifier shared
  reasoning with the investigator" invalidates the claim in VERITAS. "The evaluator shared
  information with the attacker" inflates the metric in NIDS evaluation. Same argument,
  two domains. Write this down somewhere permanent.

- **VERITAS is Career rail, not Research rail**. The CCS 2027 paper on constraint
  inflation in NIDS is the publication anchor. Do not let VERITAS architecture work eat
  that clock. VERITAS feeds the Research rail only as infrastructure.

- **Branch discipline**: `future/cross-layer-verification` only. Do NOT merge to `main`
  until Phase 2 same-layer verification is implemented and tested on nfury data.

- **`sift_server.py` layer enforcement**: `VERITAS_LAYER` env var is set on
  `StdioServerParameters.env` when spawning the MCP server subprocess. It is NOT a CLI
  arg (FastMCP may not handle extra args cleanly). The env var reads on import via
  `_LAYER = os.environ.get('VERITAS_LAYER', 'all')`. The binary allowlist used in
  `_validate_command()` calls `_effective_allowlist()` which returns `_DISK_BINARIES`,
  `_MEMORY_BINARIES`, or `_ALLOWED_BINARIES` depending on `_LAYER`. Structural rejection
  happens before any `subprocess.run()`.

- **`disk_agent.py` investigation budget**: `MAX_ROUNDS=5, TOOLS_PER_ROUND=3`. The loop
  checks `tool_count < MAX_ROUNDS * TOOLS_PER_ROUND` (15). This is Phase 1 budget.
  Phase 2 verifier budget is separate: `MAX_VERIFY_ROUNDS=2, TOOLS_PER_VERIFY=2` (4
  calls per claim). These must not be conflated.

- **nfury test data**: Mounted disk at `/mnt/nfury`, memory image at case directory
  discovered via `_discover_case()`. SIFT workstation at `192.168.1.71` (may be offline —
  check with `ping 192.168.1.71` before testing). nfury has 15 confirmed techniques in
  the existing `reports/nfury-auditor-transcript.json` — use this as ground truth for
  Phase 2 output validation.
