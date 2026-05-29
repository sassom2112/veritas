#!/usr/bin/env python3
"""
Generate adversa_guardrails.pdf — single-column portrait A4 layout.
Run: python3 docs/gen_guardrails.py
"""
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white

OUT = "docs/adversa_guardrails.pdf"

PAGE_W, PAGE_H = A4   # 595 × 841 pt (portrait)

# ── Palette ───────────────────────────────────────────────────────────────────
NAVY     = HexColor('#1F3864')
ORANGE   = HexColor('#ED7D31')
BLUE_BG  = HexColor('#D6E4F7')
BLUE_FG  = HexColor('#1F4E79')
ORG_BG   = HexColor('#FDE9D5')
ORG_FG   = HexColor('#B05010')
GRAY_BG  = HexColor('#F2F2F2')
GRAY_FG  = HexColor('#767676')
RED_BG   = HexColor('#FDEAEA')
RED_FG   = HexColor('#C00000')
CYN_BG   = HexColor('#E0F4F4')
CYN_FG   = HexColor('#0E7070')
PUR_BG   = HexColor('#EEE5F8')
PUR_FG   = HexColor('#5B2C8D')
DRK_BG   = HexColor('#E8E8E8')
DRK_FG   = HexColor('#333333')
SEP_BG   = HexColor('#D4D4D4')
RISK_BG  = HexColor('#FFFBE5')
RISK_FG  = HexColor('#8A6C00')
GREEN    = HexColor('#006600')
AMBER    = HexColor('#CC5500')
CRIMSON  = HexColor('#990000')

# ── Layout ────────────────────────────────────────────────────────────────────
L_MARGIN  = 18          # left edge of main column
COL_W     = 420         # main column width
CALL_GAP  = 10          # gap between col right edge and callout left
CALL_X    = L_MARGIN + COL_W + CALL_GAP
CALL_W    = PAGE_W - CALL_X - 8   # ~139 pt — plenty of room
COL_CX    = L_MARGIN + COL_W / 2
ARROW_GAP = 7

# ── Primitives ────────────────────────────────────────────────────────────────
def rbox(c, x, y, w, h, bg, fg, lw=1.3, r=5, dashed=False):
    c.setFillColor(bg)
    c.setStrokeColor(fg)
    c.setLineWidth(lw)
    if dashed:
        c.setDash([5, 3])
    c.roundRect(x, y, w, h, r, fill=1, stroke=1)
    if dashed:
        c.setDash([])

def arrow_down(c, cx, y_top, y_bot, color, lw=1.4):
    c.setStrokeColor(color)
    c.setFillColor(color)
    c.setLineWidth(lw)
    shaft_end = y_bot + 7
    c.line(cx, y_top, cx, shaft_end)
    p = c.beginPath()
    p.moveTo(cx, y_bot)
    p.lineTo(cx - 5, shaft_end)
    p.lineTo(cx + 5, shaft_end)
    p.close()
    c.drawPath(p, fill=1, stroke=0)

def ct(c, cx, y, text, font, size, color):
    c.setFont(font, size)
    c.setFillColor(color)
    c.drawCentredString(cx, y, text)

def sec_header(c, x, y, w, text):
    h = 13
    rbox(c, x, y - h, w, h, NAVY, NAVY, r=3)
    ct(c, x + w/2, y - h + 3, text, 'Helvetica-Bold', 6.5, white)
    return y - h - 5

def callout(c, cx_box, box_mid_y, label, lines):
    """Draw ellipse callout to the right of the main column."""
    n = len(lines)
    ELL_H = 16 + n * 10
    ELL_W = CALL_W
    ex = CALL_X
    ey = box_mid_y - ELL_H / 2
    # dashed link
    c.setStrokeColor(GRAY_FG)
    c.setLineWidth(0.6)
    c.setDash([3, 2])
    c.line(L_MARGIN + COL_W, box_mid_y, ex, box_mid_y)
    c.setDash([])
    # ellipse
    c.setFillColor(RISK_BG)
    c.setStrokeColor(RISK_FG)
    c.setLineWidth(0.9)
    c.ellipse(ex, ey, ex + ELL_W, ey + ELL_H, fill=1, stroke=1)
    ecx = ex + ELL_W / 2
    ty = ey + ELL_H - 11
    ct(c, ecx, ty, label, 'Helvetica-Bold', 6, RISK_FG)
    for line in lines:
        ty -= 9.5
        ct(c, ecx, ty, line, 'Helvetica', 5.5, DRK_FG)


# ─────────────────────────────────────────────────────────────────────────────
c = canvas.Canvas(OUT, pagesize=A4)
c.setTitle("VERITAS Guardrails — Anti-Hallucination Trust Chain & MCP Security Boundary")

# ── Title bar ─────────────────────────────────────────────────────────────────
TH = 22
rbox(c, 0, PAGE_H - TH, PAGE_W, TH, NAVY, NAVY, r=0)
ct(c, PAGE_W/2, PAGE_H - TH + 6.5,
   "VERITAS Architecture: Anti-Hallucination Trust Chain & MCP Security Boundary",
   'Helvetica-Bold', 10, white)
c.setStrokeColor(ORANGE)
c.setLineWidth(2)
c.line(0, PAGE_H - TH, PAGE_W, PAGE_H - TH)

y = PAGE_H - TH - 7

# ══════════════════════════════════════════════════════════════════════════════
#  ANTI-HALLUCINATION TRUST CHAIN
# ══════════════════════════════════════════════════════════════════════════════
y = sec_header(c, L_MARGIN, y, COL_W, "ANTI-HALLUCINATION TRUST CHAIN")

# ── Triage Agent ──────────────────────────────────────────────────────────────
BH = 80
rbox(c, L_MARGIN, y - BH, COL_W, BH, BLUE_BG, BLUE_FG, lw=1.5)
ty = y - 10
ct(c, COL_CX, ty,  "Phase 1 — Triage Agent  (blue_agent.py)", 'Helvetica-Bold', 8.5, BLUE_FG)
ty -= 12
ct(c, COL_CX, ty,  "Pass 1: ~25 deterministic SIFT commands · ASL detection scoring", 'Helvetica', 7, DRK_FG)
ty -= 10
ct(c, COL_CX, ty,  "Pass 2: Claude agentic loop · extracts IOCs · scores MITRE techniques", 'Helvetica', 7, DRK_FG)
ty -= 10
ct(c, COL_CX, ty,  "Output: triage_report.json — findings rated HIGH / MED / LOW", 'Helvetica', 7, DRK_FG)
ty -= 12
ct(c, COL_CX, ty,  "triage_report.json  →  {technique_id, confidence_score, matched_signals}", 'Helvetica-Oblique', 6.5, GRAY_FG)

triage_top = y
triage_bot = y - BH
callout(c, COL_CX, triage_bot + BH/2, "Hallucination Risk",
        ["LLM confidence ≠ physical evidence",
         "controller: Triage raw score 145",
         "(uncapped) — Auditor refuted 2 of 3"])

arrow_down(c, COL_CX, triage_bot, triage_bot - ARROW_GAP, BLUE_FG)
y = triage_bot - ARROW_GAP - 1

# ── Independence Barrier ──────────────────────────────────────────────────────
IBH = 34
rbox(c, L_MARGIN, y - IBH, COL_W, IBH, GRAY_BG, GRAY_FG, lw=0.9, dashed=True)
ct(c, COL_CX, y - IBH/2 + 5,  "Independence Barrier", 'Helvetica-Bold', 7.5, DRK_FG)
ct(c, COL_CX, y - IBH/2 - 4,  "Auditor receives only {technique_id, score, filepath} — Triage reasoning chain and tool outputs stripped", 'Helvetica', 6, GRAY_FG)
ct(c, COL_CX, y - IBH/2 - 13, "No shared context.   No shared model state.", 'Helvetica', 6, GRAY_FG)
barrier_bot = y - IBH

arrow_down(c, COL_CX, barrier_bot, barrier_bot - ARROW_GAP, BLUE_FG)
y = barrier_bot - ARROW_GAP - 1

# ── Forensic Auditor ──────────────────────────────────────────────────────────
ABH = 74
rbox(c, L_MARGIN, y - ABH, COL_W, ABH, ORG_BG, ORG_FG, lw=1.5)
ay = y - 10
ct(c, COL_CX, ay,  "Phase 2 — Forensic Auditor  (auditor_agent.py)", 'Helvetica-Bold', 8.5, ORG_FG)
ay -= 12
ct(c, COL_CX, ay,  "asyncio.gather · 3 verification rounds × 2 independent tool calls per technique", 'Helvetica', 7, DRK_FG)
ay -= 10
ct(c, COL_CX, ay,  "Re-executes SIFT commands from scratch · demands physical bytes on disk", 'Helvetica', 7, DRK_FG)
ay -= 12
ct(c, COL_CX, ay,  "Mandate: assume every finding is a false positive", 'Helvetica-Oblique', 7, ORG_FG)
ay -= 10
ct(c, COL_CX, ay,  "until the filesystem proves otherwise", 'Helvetica-Oblique', 7, ORG_FG)

# Self-loop
aud_bot = y - ABH
ar = L_MARGIN + COL_W
lm = aud_bot + ABH * 0.5
c.setStrokeColor(ORG_FG)
c.setLineWidth(0.9)
c.bezier(ar, lm+16, ar+20, lm+26, ar+20, lm-12, ar, lm-16)
c.setFillColor(ORG_FG)
p = c.beginPath()
p.moveTo(ar, lm-16); p.lineTo(ar+8, lm-12); p.lineTo(ar+8, lm-20); p.close()
c.drawPath(p, fill=1, stroke=0)
c.setFont('Helvetica-Oblique', 5.5); c.setFillColor(GRAY_FG)
c.drawCentredString(ar+24, lm, "3 rounds")

arrow_down(c, COL_CX, aud_bot, aud_bot - ARROW_GAP, ORG_FG)
y = aud_bot - ARROW_GAP - 1

# ── Verdict Gate ──────────────────────────────────────────────────────────────
VBH = 74
rbox(c, L_MARGIN, y - VBH, COL_W, VBH, GRAY_BG, GRAY_FG, lw=1.0)
vy = y - 10
ct(c, COL_CX, vy, "Verdict Gate", 'Helvetica-Bold', 8.5, DRK_FG)
vy -= 13
# CONFIRMED
c.setFont('Helvetica-Bold', 7); c.setFillColor(GREEN)
c.drawString(L_MARGIN + 14, vy, "CONFIRMED")
c.setFont('Helvetica', 7); c.setFillColor(DRK_FG)
c.drawString(L_MARGIN + 90, vy, "— physical artifact verified on disk")
vy -= 9
c.setFont('Helvetica', 6.5); c.setFillColor(GRAY_FG)
c.drawString(L_MARGIN + 20, vy, "→  enters report & propagates to subsequent hosts")
vy -= 12
# INCONCLUSIVE
c.setFont('Helvetica-Bold', 7); c.setFillColor(AMBER)
c.drawString(L_MARGIN + 14, vy, "INCONCLUSIVE")
c.setFont('Helvetica', 7); c.setFillColor(DRK_FG)
c.drawString(L_MARGIN + 100, vy, "— insufficient physical evidence")
vy -= 9
c.setFont('Helvetica', 6.5); c.setFillColor(GRAY_FG)
c.drawString(L_MARGIN + 20, vy, "→  logged to audit trail, suppressed from report")
vy -= 12
# REFUTED
c.setFont('Helvetica-Bold', 7); c.setFillColor(CRIMSON)
c.drawString(L_MARGIN + 14, vy, "REFUTED")
c.setFont('Helvetica', 7); c.setFillColor(DRK_FG)
c.drawString(L_MARGIN + 80, vy, "— evidence absent or contradicted")
vy -= 9
c.setFont('Helvetica', 6.5); c.setFillColor(GRAY_FG)
c.drawString(L_MARGIN + 20, vy, "→  dropped from all outputs")

vrd_bot = y - VBH
callout(c, COL_CX, vrd_bot + VBH/2, "Live Result",
        ["controller host",
         "Triage raw: 145 pts (3 techniques)",
         "Auditor refuted: 2",
         "Final score: 50 pts",
         "Zero false accusations"])

arrow_down(c, COL_CX, vrd_bot, vrd_bot - ARROW_GAP, GRAY_FG)
y = vrd_bot - ARROW_GAP - 1

# ── Separator ─────────────────────────────────────────────────────────────────
SH = 18
rbox(c, L_MARGIN, y - SH, COL_W, SH, SEP_BG, GRAY_FG, lw=0.8, r=4)
ct(c, COL_CX, y - SH/2 - 3.5,
   "Every tool call passes through  sift_server.py  before execution",
   'Helvetica-Oblique', 6.5, DRK_FG)
sep_bot = y - SH

arrow_down(c, COL_CX, sep_bot, sep_bot - ARROW_GAP, GRAY_FG)
y = sep_bot - ARROW_GAP - 1

# ══════════════════════════════════════════════════════════════════════════════
#  MCP SECURITY BOUNDARY
# ══════════════════════════════════════════════════════════════════════════════
y = sec_header(c, L_MARGIN, y, COL_W, "MCP SECURITY BOUNDARY  (sift_server.py)")

GH = 62
GG = 8

# ── Gate 1 ────────────────────────────────────────────────────────────────────
rbox(c, L_MARGIN, y - GH, COL_W, GH, RED_BG, RED_FG, lw=1.5)
g1y = y - 10
ct(c, COL_CX, g1y, "Gate ① — Hard-Blocked Strings", 'Helvetica-Bold', 8.5, RED_FG)
g1y -= 12
ct(c, COL_CX, g1y, "26 hard-blocked strings:  shred  mkfs  fdisk  wget  curl  ssh  sudo  $(  system(", 'Helvetica', 6.8, DRK_FG)
g1y -= 10
ct(c, COL_CX, g1y, "Destructive · exfil · privilege escalation · injection substitution", 'Helvetica', 6.5, DRK_FG)
g1y -= 11
ct(c, COL_CX, g1y, "Rejected before any further parsing — no exceptions, no prompt-level overrides", 'Helvetica-Oblique', 6.5, RED_FG)
g1_bot = y - GH

arrow_down(c, COL_CX, g1_bot, g1_bot - GG, RED_FG)
y = g1_bot - GG - 1

# ── Gate 2 ────────────────────────────────────────────────────────────────────
rbox(c, L_MARGIN, y - GH, COL_W, GH, ORG_BG, ORG_FG, lw=1.5)
g2y = y - 10
ct(c, COL_CX, g2y, "Gate ② — Binary Allowlist", 'Helvetica-Bold', 8.5, ORG_FG)
g2y -= 12
ct(c, COL_CX, g2y, "71 approved forensic binaries:", 'Helvetica', 6.8, DRK_FG)
g2y -= 10
ct(c, COL_CX, g2y, "vol.py · fls · icat · rip.pl · yara · strings · grep · md5sum · xxd · find · bulk_extractor …", 'Helvetica', 6.5, DRK_FG)
g2y -= 10
ct(c, COL_CX, g2y, "Note: sed excluded — GNU sed -e flag executes arbitrary shell commands", 'Helvetica-Oblique', 6, GRAY_FG)
g2y -= 10
ct(c, COL_CX, g2y, "Unknown binaries rejected unconditionally — allowlist cannot be extended via prompt", 'Helvetica-Oblique', 6.5, ORG_FG)
g2_bot = y - GH

arrow_down(c, COL_CX, g2_bot, g2_bot - GG, ORG_FG)
y = g2_bot - GG - 1

# ── Gate 3 ────────────────────────────────────────────────────────────────────
rbox(c, L_MARGIN, y - GH, COL_W, GH, CYN_BG, CYN_FG, lw=1.5)
g3y = y - 10
ct(c, COL_CX, g3y, "Gate ③ — Quote-Aware Pipe Parser", 'Helvetica-Bold', 8.5, CYN_FG)
g3y -= 12
ct(c, COL_CX, g3y, "Full command tokenised respecting single/double quoting", 'Helvetica', 6.8, DRK_FG)
g3y -= 10
ct(c, COL_CX, g3y, "Each pipe segment validated independently against Gates ① and ②", 'Helvetica', 6.8, DRK_FG)
g3y -= 10
ct(c, COL_CX, g3y, "Per-binary guards: python3 -c blocked · find -exec target must be in allowlist", 'Helvetica', 6.5, DRK_FG)
g3y -= 10
ct(c, COL_CX, g3y, "Blocks injection through $() subshells, piped interpreters, embedded newlines", 'Helvetica-Oblique', 6.5, CYN_FG)
g3_bot = y - GH

arrow_down(c, COL_CX, g3_bot, g3_bot - GG, CYN_FG)
y = g3_bot - GG - 1

# ── Gate 4 ────────────────────────────────────────────────────────────────────
rbox(c, L_MARGIN, y - GH, COL_W, GH, PUR_BG, PUR_FG, lw=1.5)
g4y = y - 10
ct(c, COL_CX, g4y, "Gate ④ — Redirect Guard", 'Helvetica-Bold', 8.5, PUR_FG)
g4y -= 12
ct(c, COL_CX, g4y, "All > and >> redirects verified to target reports/ only", 'Helvetica', 6.8, DRK_FG)
g4y -= 10
ct(c, COL_CX, g4y, "Evidence paths (/mnt/host) are structurally write-protected", 'Helvetica', 6.8, DRK_FG)
g4y -= 10
ct(c, COL_CX, g4y, "audit_log.jsonl explicitly denied as write target", 'Helvetica', 6.5, DRK_FG)
g4y -= 10
ct(c, COL_CX, g4y, "Evidence modification is architecturally impossible — not prompt-dependent", 'Helvetica-Oblique', 6.5, PUR_FG)
g4_bot = y - GH

arrow_down(c, COL_CX, g4_bot, g4_bot - GG, PUR_FG)
y = g4_bot - GG - 1

# ── Structural Guarantee ──────────────────────────────────────────────────────
GURH = 48
rbox(c, L_MARGIN, y - GURH, COL_W, GURH, DRK_BG, DRK_FG, lw=1.8)
gy = y - 10
ct(c, COL_CX, gy, "Structural Guarantee", 'Helvetica-Bold', 8.5, DRK_FG)
gy -= 12
ct(c, COL_CX, gy, "Both anti-hallucination and security properties are enforced architecturally,", 'Helvetica', 7, DRK_FG)
gy -= 10
ct(c, COL_CX, gy, "not through prompt instructions.", 'Helvetica', 7, DRK_FG)
gy -= 11
ct(c, COL_CX, gy, "Every command execution is atomically appended to audit_log.jsonl for audit.", 'Helvetica-Oblique', 6.5, GRAY_FG)

guar_bot = y - GURH

# ── Caption ───────────────────────────────────────────────────────────────────
c.setFont('Helvetica-Oblique', 6)
c.setFillColor(GRAY_FG)
c.drawCentredString(PAGE_W/2, guar_bot - 12,
    "VERITAS Guardrails — Anti-Hallucination Trust Chain & MCP Security Boundary  "
    "·  github.com/sassom2112/adversa")

c.save()
print(f"Written: {OUT}   (bottom of content at y={guar_bot:.0f}, page bottom at 0)")
