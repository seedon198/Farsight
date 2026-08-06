#!/usr/bin/env python3
"""Capture real screenshots for offline replay by `farsight web --demo`.

Not part of the installed package -- a standalone rehearsal tool, same
spirit as capture_demo_fixture.py. Run it (with network + `playwright
install chromium`) against domains you have rights to screenshot before
going offline; /api/screenshot then serves these bundled PNGs instead
of making a live capture while demo mode is active.

capture_demo_fixture.py already does this as part of a normal capture.
This script exists for the split flow: when the scan itself needs root
(masscan uses raw sockets), the screenshot pass should still run as your
normal user rather than driving a browser as root, so capture the
fixture under sudo with --no-screenshots and then run this against it.

Usage:
    python scripts/capture_demo_screenshots.py example.com sub.example.com
    python scripts/capture_demo_screenshots.py --from-fixture \\
        farsight/web/fixtures/demo_scan_example.com.json
"""

import argparse
import asyncio
import json
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


def _domains_from_fixture(fixture_path: Path, limit: int) -> list:
    """Target plus the highest-risk lookalikes that actually serve HTTP.

    Mirrors capture_demo_fixture.py's selection so both entry points
    bundle the same set.
    """
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    domain = fixture.get("domain")
    typosquats = ((fixture.get("results") or {}).get("typosquat") or {}).get(
        "typosquats"
    ) or []

    live = [
        t
        for t in typosquats
        if t.get("domain") and (t.get("http_status") or 0) in range(200, 400)
    ]
    live.sort(key=lambda t: t.get("risk_score", 0), reverse=True)

    domains = [domain] if domain else []
    for t in live:
        if t["domain"] not in domains:
            domains.append(t["domain"])
        if len(domains) >= limit + 1:  # +1 for the real site itself
            break
    return domains


async def _capture_all(domains: list) -> int:
    if not screenshot.PLAYWRIGHT_AVAILABLE:
        print(screenshot.NOT_INSTALLED_HINT, file=sys.stderr)
        raise SystemExit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for domain in domains:
        try:
            image = await screenshot.capture_domain(domain)
        except Exception as e:
            # A lookalike that refuses to load is normal, not a run failure.
            print(f"  skipped {domain}: {e}", file=sys.stderr)
            continue
        (OUTPUT_DIR / f"{domain}.png").write_bytes(image)
        print(f"  wrote {domain}.png")
        written += 1
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "domains",
        nargs="*",
        help="Domains to screenshot (must be ones you have rights to access)",
    )
    parser.add_argument(
        "--from-fixture",
        type=Path,
        default=None,
        help="Read the target and its live lookalikes from a captured fixture",
    )
    parser.add_argument(
        "--max-screenshots",
        type=int,
        default=8,
        help="How many lookalikes to capture when using --from-fixture",
    )
    args = parser.parse_args()

    domains = list(args.domains)
    if args.from_fixture:
        domains = _domains_from_fixture(args.from_fixture, args.max_screenshots)
    if not domains:
        parser.error("give at least one domain, or use --from-fixture")

    print(f"Capturing {len(domains)} screenshot(s) into {OUTPUT_DIR}...")
    written = asyncio.run(_capture_all(domains))
    print(f"Wrote {written}/{len(domains)} screenshot(s).")


if __name__ == "__main__":
    main()
