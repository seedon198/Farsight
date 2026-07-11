"""Server-side scan/report state for the web UI.

Two responsibilities, both existing to work around constraints in the
underlying farsight package rather than being "nice to have":

1. Enforce a single scan at a time. farsight.config.DEFAULT_CONFIG is a
   shared module-level dict that run_scan()-style code mutates per call
   for timeout/concurrency settings; two concurrent scans would race and
   clobber each other's settings. This is a local single-operator demo
   tool, so serializing scans is the correct fix, not a config refactor.

2. Track generated reports by an opaque id rather than exposing
   filesystem paths to the client, so report download endpoints can't
   be used for path traversal.
"""

import asyncio
import uuid
from pathlib import Path
from typing import Dict, Optional


class ScanManager:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._running = False
        self._reports: Dict[str, Dict[str, Optional[Path]]] = {}

    async def try_start(self) -> bool:
        """Attempt to claim the single scan slot. Returns False if busy."""
        async with self._lock:
            if self._running:
                return False
            self._running = True
            return True

    async def finish(self) -> None:
        async with self._lock:
            self._running = False

    def register_report(self, md_path: Path, pdf_path: Optional[Path] = None) -> str:
        report_id = uuid.uuid4().hex
        self._reports[report_id] = {"md": md_path, "pdf": pdf_path}
        return report_id

    def get_report(self, report_id: str) -> Optional[Dict[str, Optional[Path]]]:
        return self._reports.get(report_id)


# Single process-wide instance, imported by the FastAPI app and orchestrator.
scan_manager = ScanManager()
