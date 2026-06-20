#!/usr/bin/env bash
# veritas.sh — VERITAS Investigation Framework
#
# Usage:
#   ./veritas.sh /mnt/nfury
#   ./veritas.sh --no-synthesis /mnt/controller
#   ./veritas.sh --help
#
# If ANTHROPIC_API_KEY is not set, prompts securely.
# Checks that the target mount point is non-empty before running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[0;34m'; D='\033[2m'; N='\033[0m'

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${B}  ╔══════════════════════════════════════════════════╗${N}"
echo -e "${B}  ║${N}   VERITAS — Adversarial Signal Learning          ${B}║${N}"
echo -e "${B}  ║${N}   Forensic Triage + Auditor Pipeline             ${B}║${N}"
echo -e "${B}  ╚══════════════════════════════════════════════════╝${N}"
echo ""

# ── Help ──────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo -e "  ${C}Usage:${N}"
    echo "    ./veritas.sh [--no-synthesis] [--ioc-file PATH] <mount_path>"
    echo ""
    echo -e "  ${C}Examples:${N}"
    echo "    ./veritas.sh /mnt/nfury"
    echo "    ./veritas.sh --no-synthesis /mnt/controller    # fast, no LLM synthesis"
    echo "    ./veritas.sh --ioc-file reports/host1-iocs.json /mnt/host2  # IOC correlation"
    echo ""
    echo -e "  ${C}Multi-host campaign workflow:${N}"
    echo "    ./veritas.sh /mnt/host1                        # step 1: baseline"
    echo "    ./veritas.sh --ioc-file reports/host1-iocs.json /mnt/host2  # step 2"
    echo "    ./veritas-merge-iocs.sh reports/host1-iocs.json reports/host2-iocs.json \\"
    echo "        > reports/network1-campaign.json            # merge"
    echo "    ./veritas.sh --ioc-file reports/network1-campaign.json /mnt/host3  # step 3"
    echo ""
    echo -e "  ${C}Mount a disk image first:${N}"
    echo "    sudo ewfmount image.E01 /mnt/ewf_host"
    echo "    sudo mount -o ro,loop,offset=1048576,uid=\$(id -u) /mnt/ewf_host/ewf1 /mnt/host"
    echo ""
    echo -e "  ${C}API key:${N}"
    echo "    Set ANTHROPIC_API_KEY in your environment, or enter it when prompted."
    echo ""
    exit 0
fi

# ── API key ───────────────────────────────────────────────────────────────────
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo -e "  ${Y}ANTHROPIC_API_KEY not set.${N}"
    echo ""
    read -r -s -p "  Enter Anthropic API key (sk-ant-...): " _key
    echo ""

    if [[ ! "$_key" =~ ^sk-ant- ]]; then
        echo -e "\n  ${R}ERROR: Key must start with 'sk-ant-'${N}"
        exit 1
    fi

    export ANTHROPIC_API_KEY="$_key"
    echo -e "  ${G}API key accepted.${N}"
    echo ""
fi

# ── Parse arguments ───────────────────────────────────────────────────────────
NO_SYNTHESIS=""
IOC_FILE=""
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-synthesis) NO_SYNTHESIS="--no-synthesis"; shift ;;
        --ioc-file)
            if [[ -z "${2:-}" ]]; then
                echo -e "  ${R}--ioc-file requires a path argument${N}"; exit 1
            fi
            IOC_FILE="--ioc-file $2"; shift 2 ;;
        --*)
            echo -e "  ${R}Unknown option: $1${N}"
            echo "  Run ./veritas.sh --help for usage."
            exit 1
            ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo -e "  ${C}No mount path provided.${N}"
    read -r -p "  Enter mount path (e.g. /mnt/nfury): " TARGET
    echo ""
fi

# ── Mount check ───────────────────────────────────────────────────────────────
if [[ ! -d "$TARGET" ]]; then
    echo -e "  ${R}ERROR: '$TARGET' is not a directory.${N}"
    exit 1
fi

if [[ -z "$(ls -A "$TARGET" 2>/dev/null)" ]]; then
    echo -e "  ${R}ERROR: '$TARGET' is empty — image not mounted.${N}"
    echo ""
    echo -e "  ${Y}Mount steps:${N}"
    HOST_NAME="$(basename "$TARGET")"
    echo "    sudo ewfmount <image.E01> /mnt/ewf_${HOST_NAME}"
    echo "    sudo mmls /mnt/ewf_${HOST_NAME}/ewf1                    # find partition offset"
    echo "    sudo mount -o ro,loop,offset=<sectors*512>,uid=\$(id -u) /mnt/ewf_${HOST_NAME}/ewf1 $TARGET"
    echo ""
    exit 1
fi

# ── Activate virtual environment if present ───────────────────────────────────
if [[ -f "$HOME/swift-agent-env/bin/activate" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/swift-agent-env/bin/activate"
elif [[ -f "$SCRIPT_DIR/swift-agent-env/bin/activate" ]]; then
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/swift-agent-env/bin/activate"
fi

# ── Run investigation ─────────────────────────────────────────────────────────
HOST_NAME="$(basename "$TARGET")"
echo -e "  ${C}Target:${N}  $TARGET"
echo -e "  ${C}Mode:${N}    ${NO_SYNTHESIS:+fast (--no-synthesis)}${NO_SYNTHESIS:-full (with LLM synthesis)}"
[[ -n "$IOC_FILE" ]] && echo -e "  ${C}IOCs:${N}    ${IOC_FILE#--ioc-file }"
echo ""

python3 "$SCRIPT_DIR/custom-agent/investigate.py" $NO_SYNTHESIS $IOC_FILE "$TARGET"

# ── Show report path ──────────────────────────────────────────────────────────
HTML_REPORT="$SCRIPT_DIR/reports/${HOST_NAME}-report.html"
if [[ -f "$HTML_REPORT" ]]; then
    echo ""
    echo -e "  ${G}HTML report:${N} $HTML_REPORT"
    echo -e "  ${D}Open with:   xdg-open $HTML_REPORT${N}"
fi
