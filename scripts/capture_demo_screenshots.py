#!/usr/bin/env python3
"""Capture real screenshots for offline replay by `farsight web --demo`.

Not part of the installed package -- a standalone rehearsal tool, same
spirit as capture_demo_fixture.py. Run it (with network + `playwright
install chromium`) against domains you have rights to screenshot before
going offline; /api/screenshot then serves these bundled PNGs instead
of making a live capture while demo mode is active.

Usage:
    python scripts/capture_demo_screenshots.py example.com
    python scripts/capture_demo_screenshots.py example.com sub.example.com other.com
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from farsight.web import screenshot  # noqa: E402

OUTPUT_DIR = (
    Path(__file__).resolve().parent.parent
    / "farsight"
    / "web"
    / "fixtures"
    / "screenshots"
)


async def _capture_all(domains: list) -> None:
    if not screenshot.PLAYWRIGHT_AVAILABLE:
        print(screenshot.NOT_INSTALLED_HINT, file=sys.stderr)
        raise SystemExit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for domain in domains:
        try:
            image = await screenshot.capture_domain(domain)
        except Exception as e:
            print(f"  FAILED {domain}: {e}", file=sys.stderr)
            continue
        out_path = OUTPUT_DIR / f"{domain}.png"
        out_path.write_bytes(image)
        print(f"  Wrote {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "domains",
        nargs="+",
        help="Domains to screenshot (must be ones you have rights to access)",
    )
    args = parser.parse_args()

    print(f"Capturing {len(args.domains)} screenshot(s) into {OUTPUT_DIR}...")
    asyncio.run(_capture_all(args.domains))


if __name__ == "__main__":
    main()
