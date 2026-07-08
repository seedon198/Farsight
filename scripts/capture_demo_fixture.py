#!/usr/bin/env python3
"""Capture a real scan's results as a JSON fixture for offline replay.

Not part of the installed package -- a standalone rehearsal tool for
`farsight web --demo`. Run it against a domain you have clear rights
to scan; the fixture captures the full scan results so the web UI can
replay them later with zero network access.

Usage:
    python scripts/capture_demo_fixture.py example.com
    python scripts/capture_demo_fixture.py example.com --depth 2 --modules org,recon,typosquat
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from farsight.web.events import ScanEvent  # noqa: E402
from farsight.web.orchestrator import run_scan_with_events  # noqa: E402


async def _capture(domain: str, depth: int, modules: list) -> dict:
    async def emit(event: ScanEvent) -> None:
        print(f"  [{event.type.value}] {event.module or ''} {event.message or ''}")

    return await run_scan_with_events(domain, depth, modules, emit)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "domain", help="Domain to scan (must be one you have rights to scan)"
    )
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument(
        "--modules",
        default="org,recon,threat,typosquat,news",
        help="Comma-separated module list",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Fixture output path (default: farsight/web/fixtures/demo_scan_<domain>.json)",
    )
    args = parser.parse_args()

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    output = args.output or (
        Path(__file__).resolve().parent.parent
        / "farsight"
        / "web"
        / "fixtures"
        / f"demo_scan_{args.domain}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)

    print(
        f"Capturing a real scan against {args.domain} "
        f"(depth={args.depth}, modules={modules})..."
    )
    results = asyncio.run(_capture(args.domain, args.depth, modules))

    fixture = {"domain": args.domain, "depth": args.depth, "results": results}
    output.write_text(json.dumps(fixture, indent=2, default=str), encoding="utf-8")
    print(f"Wrote fixture: {output}")


if __name__ == "__main__":
    main()
