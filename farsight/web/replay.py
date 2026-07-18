"""Offline replay of a previously-captured scan.

Loads a JSON fixture (the same `results` dict shape orchestrator.py
produces) and emits the identical ScanEvent sequence run_scan_with_
events() would, with artificial pacing between module start/complete
so it reads like a live scan. Because it reuses the same summary
builders and finalize_scan() as the live path, the frontend needs
zero changes to support this - useful when DEF CON's venue network
can't be relied on for a live demo.

Fixtures are captured ahead of time with scripts/capture_demo_fixture.py
and are NOT wired into farsight.cli.scan.run_scan() - this is a
web-demo-only offline capability, deliberately not a general CLI
--offline mode.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict

from farsight.utils.common import logger
from farsight.web.events import EventType, ScanEvent
from farsight.web.orchestrator import (
    MODULE_ORDER,
    SUMMARY_BUILDERS,
    EmitFn,
    finalize_scan,
)

DEFAULT_PACING_SECONDS = 1.5


async def replay_scan(
    fixture_path: Path,
    emit: EmitFn,
    pacing_seconds: float = DEFAULT_PACING_SECONDS,
) -> Dict[str, Any]:
    """Replay a pre-captured scan fixture as if it were happening live.

    Mirrors run_scan_with_events()'s top-level resilience: a malformed
    or unreadable fixture emits SCAN_FAILED instead of raising into the
    caller, so a corrupted demo fixture can't crash the WebSocket mid-
    presentation.
    """
    results: Dict[str, Any] = {}
    domain = "unknown"
    depth = 1

    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        domain = fixture.get("domain", "unknown")
        depth = fixture.get("depth", 1)
        results = fixture.get("results", {})

        await emit(
            ScanEvent(
                type=EventType.SCAN_STARTED,
                data={
                    "domain": domain,
                    "modules": list(results.keys()),
                    "replay": True,
                },
            )
        )

        for module in MODULE_ORDER:
            if module not in results:
                continue
            await emit(ScanEvent(type=EventType.MODULE_STARTED, module=module))
            await asyncio.sleep(pacing_seconds)
            try:
                summary = SUMMARY_BUILDERS[module](results[module])
            except Exception as e:
                logger.exception(f"replay: failed to summarize fixture module {module}")
                await emit(
                    ScanEvent(
                        type=EventType.MODULE_ERROR, module=module, message=str(e)
                    )
                )
                continue
            await emit(
                ScanEvent(type=EventType.MODULE_COMPLETED, module=module, data=summary)
            )

        await finalize_scan(
            results, domain, depth, list(results.keys()), emit, replay=True
        )
    except Exception as e:
        logger.exception("replay failed")
        await emit(ScanEvent(type=EventType.SCAN_FAILED, message=str(e)))

    return results
