#!/usr/bin/env python3
"""Capture a real scan's results as a JSON fixture for offline replay.

Not part of the installed package -- a standalone rehearsal tool for
`farsight web --demo`. Run it against a domain you have clear rights
to scan; the fixture captures the full scan results so the web UI can
replay them later with zero network access.

By default it also captures the screenshots the typosquat comparison
view needs (the real site plus the highest-risk lookalikes it found),
because a fixture without them replays into a UI with no previews --
the side-by-side "is this the real site?" moment is the point of that
panel. Pass --no-screenshots to skip.

Usage:
    python scripts/capture_demo_fixture.py example.com
    python scripts/capture_demo_fixture.py example.com --depth 2 --modules org,recon,typosquat
    sudo -E python scripts/capture_demo_fixture.py example.com   # enables masscan
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from farsight.utils.masscan import MasscanScanner  # noqa: E402
from farsight.web import screenshot  # noqa: E402
from farsight.web.events import ScanEvent  # noqa: E402
from farsight.web.orchestrator import run_scan_with_events  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "farsight" / "web" / "fixtures"
SCREENSHOTS_DIR = FIXTURES_DIR / "screenshots"


async def _capture(domain: str, depth: int, modules: list) -> dict:
    async def emit(event: ScanEvent) -> None:
        print(f"  [{event.type.value}] {event.module or ''} {event.message or ''}")

    return await run_scan_with_events(domain, depth, modules, emit)


def _screenshot_targets(domain: str, results: dict, limit: int) -> list:
    """The target plus the lookalikes the UI can actually show a preview for.

    Only typosquats that resolve and answer HTTP are worth capturing -- the
    rest have nothing to screenshot. Ordered by risk so a truncated capture
    keeps the most compelling comparisons.
    """
    typosquats = (results.get("typosquat") or {}).get("typosquats") or []
    live = [
        t
        for t in typosquats
        if t.get("domain") and (t.get("http_status") or 0) in range(200, 400)
    ]
    live.sort(key=lambda t: t.get("risk_score", 0), reverse=True)

    targets = [domain]
    for t in live:
        if t["domain"] not in targets:
            targets.append(t["domain"])
        if len(targets) >= limit + 1:  # +1 for the real site itself
            break
    return targets


async def _capture_screenshots(targets: list) -> None:
    if not screenshot.PLAYWRIGHT_AVAILABLE:
        print(f"\nSkipping screenshots: {screenshot.NOT_INSTALLED_HINT}")
        return

    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\nCapturing {len(targets)} screenshot(s) into {SCREENSHOTS_DIR}...")
    for target in targets:
        try:
            image = await screenshot.capture_domain(target)
        except Exception as e:
            # A lookalike that refuses to load is normal, not a failure of
            # the capture run -- note it and keep going.
            print(f"  skipped {target}: {e}")
            continue
        (SCREENSHOTS_DIR / f"{target}.png").write_bytes(image)
        print(f"  wrote {target}.png")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "domain", help="Domain to scan (must be one you have rights to scan)"
    )
    parser.add_argument("--depth", type=int, default=1)
    parser.add_argument(
        "--modules",
        default="org,recon,attack_surface,threat,typosquat,news",
        help="Comma-separated module list",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Fixture output path (default: farsight/web/fixtures/demo_scan_<domain>.json)",
    )
    parser.add_argument(
        "--no-screenshots",
        action="store_true",
        help="Skip capturing screenshots for the typosquat comparison view",
    )
    parser.add_argument(
        "--max-screenshots",
        type=int,
        default=8,
        help="How many live lookalike domains to screenshot (default: 8)",
    )
    args = parser.parse_args()

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    output = args.output or (FIXTURES_DIR / f"demo_scan_{args.domain}.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    if MasscanScanner.is_available():
        print("masscan found -- run under sudo to use it for the port scan.")
    else:
        print("masscan not found; using the built-in scanner.")

    print(
        f"Capturing a real scan against {args.domain} "
        f"(depth={args.depth}, modules={modules})..."
    )
    results = asyncio.run(_capture(args.domain, args.depth, modules))

    fixture = {"domain": args.domain, "depth": args.depth, "results": results}
    output.write_text(json.dumps(fixture, indent=2, default=str), encoding="utf-8")
    print(f"Wrote fixture: {output}")

    if args.no_screenshots:
        print("Screenshots skipped (--no-screenshots).")
        return

    targets = _screenshot_targets(args.domain, results, args.max_screenshots)
    asyncio.run(_capture_screenshots(targets))
    print(f"\nDone. Replay it with: farsight web --demo --fixture {output}")


if __name__ == "__main__":
    main()
