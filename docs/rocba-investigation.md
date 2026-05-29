---
title: rocba Investigation
nav_order: 9
permalink: /rocba
---

# rocba — Live Investigation Report

The attacker's C2 relay node. Zero disk artifacts — no persistence, no lateral movement, no staged files. This host deliberately leaves nothing on disk.

**1 confirmed · 4 refuted · ~23 minutes · ~$14**

T1055 confirmed in `MsMpEng.exe` (Windows Defender's engine): two `VadS PAGE_EXECUTE_READWRITE` regions with x64 shellcode prologue recovered before malfind timeout. The attacker injected into their own AV. Round 1 timed out — Auditor returned INCONCLUSIVE. Round 2 recovered one VAD record and returned CONFIRMED. The architecture fails safe.

The same four memory-only signals refuted here as on nfury: T1071.001, T1134, T1547.001, T1574. Consistent Auditor behavior across victim machines and attacker infrastructure.

[Open full screen](/docs/rocba-report.html){: .btn .btn-primary .mb-4 }

---

<style>
  .report-frame-wrap {
    width: 100%;
    border: 1px solid #30363d;
    border-radius: 6px;
    overflow: hidden;
  }
  .report-frame-wrap iframe {
    width: 100%;
    height: 85vh;
    border: none;
    display: block;
  }
</style>

<div class="report-frame-wrap">
  <iframe
    src="/docs/rocba-report.html"
    title="rocba VERITAS Investigation Report"
    scrolling="yes"
    loading="lazy">
  </iframe>
</div>
