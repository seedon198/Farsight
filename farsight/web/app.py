"""FastAPI application for the FARSIGHT web UI.

Local-first: intended to be run on 127.0.0.1 by a single presenter,
see farsight/cli/web.py. No auth, no multi-tenant concerns.
"""

from pathlib import Path

import markdown
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from farsight.utils.common import logger
from farsight.web.events import EventType, ScanEvent
from farsight.web.orchestrator import run_scan_with_events
from farsight.web.scan_manager import scan_manager

STATIC_DIR = Path(__file__).parent / "static"

try:
    import gnews  # noqa: F401

    GNEWS_AVAILABLE = True
except ImportError:
    GNEWS_AVAILABLE = False

DEFAULT_MODULES = ["org", "recon", "threat", "typosquat", "news"]


def create_app() -> FastAPI:
    app = FastAPI(title="FARSIGHT Web UI")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "gnews_available": GNEWS_AVAILABLE}

    @app.websocket("/ws")
    async def ws_scan(websocket: WebSocket):
        await websocket.accept()

        try:
            request = await websocket.receive_json()
        except Exception:
            await websocket.close()
            return

        domain = str(request.get("domain", "")).strip()
        try:
            depth = int(request.get("depth", 1))
        except (TypeError, ValueError):
            depth = 1
        modules = request.get("modules") or DEFAULT_MODULES

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

    return app
