"""
Export VERITAS investigation IOCs as a Splunk SPL search.

Usage:
    python export_to_splunk.py reports/<hostname>-iocs.json [--index INDEX]

Generates a ready-to-paste SPL query that hunts for VERITAS-confirmed
IOCs in a Splunk windows_events index.

Requires the Splunk Agentic IR project to be present at:
    ../splunk-agentic-ir/agent/ioc_bridge.py

Or install as a package: pip install -e ../splunk-agentic-ir
"""
import argparse
import sys
from pathlib import Path

_BRIDGE_PATH = Path(__file__).parent.parent / "splunk-agentic-ir"


def _import_bridge():
    if str(_BRIDGE_PATH) not in sys.path:
        sys.path.insert(0, str(_BRIDGE_PATH))
    try:
        from agent.ioc_bridge import adversa_to_splunk
        return adversa_to_splunk
    except ImportError as e:
        print(f"ERROR: could not import ioc_bridge from {_BRIDGE_PATH}", file=sys.stderr)
        print(f"  {e}", file=sys.stderr)
        print("  Make sure splunk-agentic-ir is cloned alongside this project.", file=sys.stderr)
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("iocs_json", type=Path, help="Path to VERITAS iocs.json output")
    p.add_argument("--index", default="windows_events", help="Splunk index name")
    p.add_argument("--out", type=Path, default=None, help="Save SPL to file instead of stdout")
    args = p.parse_args()

    if not args.iocs_json.exists():
        print(f"ERROR: {args.iocs_json} not found", file=sys.stderr)
        sys.exit(1)

    adversa_to_splunk = _import_bridge()
    spl = adversa_to_splunk(args.iocs_json, index=args.index)

    if args.out:
        args.out.write_text(spl)
        print(f"SPL saved to {args.out}")
    else:
        print(spl)


if __name__ == "__main__":
    main()
