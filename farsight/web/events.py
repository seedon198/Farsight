"""Shared WebSocket event contract for the FARSIGHT web UI.

Both the live scan orchestrator and the (future) replay engine emit
this same event shape, so the frontend never needs to know whether
it's watching a real scan or a replayed fixture.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class EventType(str, Enum):
    SCAN_STARTED = "scan_started"
    MODULE_STARTED = "module_started"
    MODULE_COMPLETED = "module_completed"
    MODULE_ERROR = "module_error"
    SCAN_COMPLETED = "scan_completed"
    REPORT_READY = "report_ready"
    SCAN_REJECTED = "scan_rejected"
    SCAN_FAILED = "scan_failed"


@dataclass
class ScanEvent:
    type: EventType
    module: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "module": self.module,
            "data": self.data,
            "message": self.message,
            "timestamp": self.timestamp,
        }
