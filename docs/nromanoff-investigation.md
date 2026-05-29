---
title: nromanoff Investigation
nav_order: 8
permalink: /nromanoff
---

# nromanoff — Live Investigation Report

Standalone investigation. Distinct tool family: `spinlock.exe` (PyInstaller Python backdoor).
External C2 confirmed at `199.73.28.114:443` with self-signed TLS cert — the only host with a live external C2 connection.
`vibranium` account and `PSEXESVC.EXE` confirmed on disk.
3 confirmed, 4 refuted. ~15 minutes. ~$14.

[Open full screen](/docs/nromanoff-report.html){: .btn .btn-primary .mb-4 }

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
    src="/docs/nromanoff-report.html"
    title="nromanoff VERITAS Investigation Report"
    scrolling="yes"
    loading="lazy">
  </iframe>
</div>
