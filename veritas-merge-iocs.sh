#!/usr/bin/env bash
# adversa-merge-iocs.sh — Merge IOC files from multiple hosts into one campaign file.
#
# Usage:
#   ./adversa-merge-iocs.sh reports/host1-iocs.json reports/host2-iocs.json > reports/campaign.json
#   ./adversa-merge-iocs.sh reports/host1-iocs.json reports/host2-iocs.json -o reports/network1-campaign.json
#
# Output goes to stdout (redirect with >) or use -o <path>.
# Then pass the result to adversa.sh:
#   ./adversa.sh --ioc-file reports/network1-campaign.json /mnt/host3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || $# -eq 0 ]]; then
    echo "Usage: ./adversa-merge-iocs.sh FILE1 FILE2 [FILE3 ...] [-o OUTPUT]"
    echo ""
    echo "Merges IOC JSON files from multiple hosts into one deduped campaign file."
    echo "Output goes to stdout unless -o PATH is given."
    echo ""
    echo "Examples:"
    echo "  ./adversa-merge-iocs.sh reports/nromanoff-iocs.json reports/nfury-iocs.json \\"
    echo "      -o reports/shield-campaign.json"
    echo "  ./adversa.sh --ioc-file reports/shield-campaign.json /mnt/tdungan"
    exit 0
fi

# Collect input files and optional -o
INPUT_FILES=()
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) OUTPUT="$2"; shift 2 ;;
        *)  INPUT_FILES+=("$1"); shift ;;
    esac
done

if [[ ${#INPUT_FILES[@]} -lt 2 ]]; then
    echo "ERROR: need at least 2 IOC files to merge" >&2
    exit 1
fi

for f in "${INPUT_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: file not found: $f" >&2
        exit 1
    fi
done

# Activate venv if present
if [[ -f "$HOME/swift-agent-env/bin/activate" ]]; then
    source "$HOME/swift-agent-env/bin/activate"
fi

# Build the host name for --host arg (join basenames without suffix)
HOST_LABEL=$(basename "${INPUT_FILES[0]}" -iocs.json)

MERGE_ARGS=("${INPUT_FILES[@]}")

if [[ -n "$OUTPUT" ]]; then
    python3 "$SCRIPT_DIR/custom-agent/extract_iocs.py" "$HOST_LABEL" \
        --merge "${MERGE_ARGS[@]}" --output "$OUTPUT"
    echo "Merged ${#INPUT_FILES[@]} IOC files -> $OUTPUT" >&2
else
    python3 "$SCRIPT_DIR/custom-agent/extract_iocs.py" "$HOST_LABEL" \
        --merge "${MERGE_ARGS[@]}" --output /dev/stdout 2>/dev/null
fi
