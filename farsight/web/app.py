"""FastAPI application for the FARSIGHT web UI.

Local-first: intended to be run on 127.0.0.1 by a single presenter,
see farsight/cli/web.py. No auth, no multi-tenant concerns.
"""

import json
import re
from pathlib import Path
from typing import Optional

import markdown
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from farsight.utils.common import logger
from farsight.web import screenshot
from farsight.web.events import EventType, ScanEvent
from farsight.web.orchestrator import MODULE_ORDER, run_scan_with_events
from farsight.web.replay import replay_scan
from farsight.web.scan_manager import scan_manager

STATIC_DIR = Path(__file__).parent / "static"
FIXTURES_DIR = Path(__file__).parent / "fixtures"
DEFAULT_FIXTURE = FIXTURES_DIR / "demo_scan_example.com.json"
DEMO_SCREENSHOTS_DIR = FIXTURES_DIR / "screenshots"

# Conservative hostname check -- this only guards a filesystem lookup
# (fixtures/screenshots/<domain>.png), not a network request, but a
# domain arriving with path separators or ".." should never turn into
# a path outside that directory.
_SAFE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}$")


def _load_demo_screenshot(domain: str) -> Optional[bytes]:
    """Return bundled PNG bytes for `domain` in demo mode, or None if none
    was captured ahead of time. See scripts/capture_demo_screenshots.py."""
    if not _SAFE_DOMAIN_RE.match(domain):
        return None
    path = DEMO_SCREENSHOTS_DIR / f"{domain}.png"
    if not path.is_file():
        return None
    return path.read_bytes()


try:
    import gnews  # noqa: F401

    GNEWS_AVAILABLE = True
except ImportError:
    GNEWS_AVAILABLE = False

DEFAULT_MODULES = ["org", "recon", "attack_surface", "threat", "typosquat", "news"]


def create_app(demo_fixture: Optional[Path] = None) -> FastAPI:
    """Build the FastAPI app.

    If `demo_fixture` is set, every scan request replays that captured
    fixture instead of hitting the network -- see farsight/web/replay.py.
    Used by `farsight web --demo` as an offline-safe fallback when the
    venue network can't be relied on.
    """
    app = FastAPI(title="FARSIGHT Web UI")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health():
        # In demo mode the replayed fixture dictates the target, so hand the
        # UI that domain to prefill -- otherwise the form's `required` field
        # sits empty and silently blocks submission on a button the
        # presenter has every reason to expect to just work.
        demo_domain = None
        if demo_fixture is not None:
            try:
                demo_domain = json.loads(demo_fixture.read_text(encoding="utf-8")).get(
                    "domain"
                )
            except Exception:
                logger.warning("could not read domain from demo fixture")

        return {
            "status": "ok",
            "gnews_available": GNEWS_AVAILABLE,
            "demo_mode": demo_fixture is not None,
            "demo_domain": demo_domain,
        }

    @app.websocket("/ws")
    async def ws_scan(websocket: WebSocket):
        await websocket.accept()

        try:
            request = await websocket.receive_json()
        except Exception:
            await websocket.close()
            return

        domain, depth, modules = None, 1, DEFAULT_MODULES
        if demo_fixture is None:
            domain = str(request.get("domain", "")).strip()
            try:
                depth = int(request.get("depth", 1))
            except (TypeError, ValueError):
                depth = 1
            requested = request.get("modules")
            # A client sending a bare string instead of a list would become
            # a set of single characters downstream, silently running no
            # modules at all. Accept only a list of known module names.
            if isinstance(requested, list):
                modules = [m for m in requested if m in MODULE_ORDER] or DEFAULT_MODULES
            else:
                modules = DEFAULT_MODULES

            if not domain:
                await websocket.send_json(
                    ScanEvent(
                        type=EventType.SCAN_REJECTED, message="domain is required"
                    ).to_dict()
                )
                await websocket.close()
                return

        if not await scan_manager.try_start():
            await websocket.send_json(
                ScanEvent(
                    type=EventType.SCAN_REJECTED,
                    message="a scan is already in progress",
                ).to_dict()
            )
            await websocket.close()
            return

        async def emit(event: ScanEvent) -> None:
            try:
                await websocket.send_json(event.to_dict())
            except Exception:
                # Client disconnected mid-scan; keep the scan running
                # server-side rather than raising into the orchestrator,
                # where it would be misreported as a module failure.
                logger.debug("websocket send failed, client likely disconnected")

        try:
            if demo_fixture is not None:
                await replay_scan(demo_fixture, emit)
            else:
                await run_scan_with_events(domain, depth, modules, emit)
        finally:
            await scan_manager.finish()
            try:
                await websocket.close()
            except Exception:
                pass

    @app.get("/api/report/{report_id}/html", response_class=HTMLResponse)
    async def report_html(report_id: str):
        report = scan_manager.get_report(report_id)
        if report is None or report.get("md") is None:
            raise HTTPException(status_code=404, detail="report not found")
        text = report["md"].read_text(encoding="utf-8")
        html = markdown.markdown(text, extensions=["tables"])
        return HTMLResponse(content=html)

    @app.get("/api/report/{report_id}/download")
    async def report_download(report_id: str, fmt: str = "md"):
        report = scan_manager.get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")

        if fmt == "pdf":
            path, media_type = report.get("pdf"), "application/pdf"
        else:
            path, media_type = report.get("md"), "text/markdown"

        if path is None or not path.exists():
            raise HTTPException(status_code=404, detail=f"{fmt} report not available")
        return FileResponse(path, media_type=media_type, filename=path.name)

    @app.get("/api/screenshot")
    async def get_screenshot(domain: str):
        if demo_fixture is not None:
            # Demo mode promises zero network calls -- never fall through
            # to a live Playwright capture here, even if one would work.
            image = _load_demo_screenshot(domain)
            if image is not None:
                return Response(content=image, media_type="image/png")
            return JSONResponse(
                status_code=404,
                content={
                    "error": "no_demo_screenshot",
                    "hint": (
                        f"No bundled screenshot for {domain} in demo mode. "
                        "Capture one ahead of time with "
                        "scripts/capture_demo_screenshots.py."
                    ),
                },
            )

        if not screenshot.PLAYWRIGHT_AVAILABLE:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "playwright_not_installed",
                    "hint": screenshot.NOT_INSTALLED_HINT,
                },
            )
        try:
            image = await screenshot.capture_domain(domain)
        except Exception:
            return JSONResponse(status_code=502, content={"error": "unreachable"})
        return Response(content=image, media_type="image/png")

    return app
