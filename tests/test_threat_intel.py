"""Tests for farsight.modules.threat_intel.

Covers two stacked IntelX bugs found while debugging a live scan:

1. Date parsing: IntelX returns `date` as an ISO-8601 string (e.g.
   "2026-07-13T00:50:45.484249Z"), not a Unix epoch number, but the
   code previously passed it straight into time.localtime(), which
   requires a number and raised "TypeError: 'str' object cannot be
   interpreted as an integer".
2. Await mismatch: _check_intelx called the (synchronous, non-async)
   _process_intelx_results with `await`, which raised
   "TypeError: 'NoneType' object can't be awaited" once (1) was fixed
   and the sync call could actually return cleanly.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from farsight.modules.threat_intel import ThreatIntel


def test_process_intelx_results_parses_iso_date_string():
    threat_intel = ThreatIntel()
    records = [
        {
            "bucket": "pastes",
            "name": "Example Paste",
            "date": "2026-07-13T00:50:45.484249Z",
            "snippet": "leaked content",
        }
    ]

    threat_intel._process_intelx_results(records, "example.com")

    assert len(threat_intel.results["leaks"]) == 1
    assert threat_intel.results["leaks"][0]["date"] == "2026-07-13"


def test_process_intelx_results_handles_missing_date():
    threat_intel = ThreatIntel()
    records = [
        {
            "bucket": "darknet",
            "name": "Example",
            "date": "",
            "snippet": "dark web mention",
        }
    ]

    threat_intel._process_intelx_results(records, "example.com")

    assert threat_intel.results["dark_web"][0]["date"] == "Unknown"


@pytest.mark.asyncio
async def test_check_intelx_does_not_await_sync_result_processing(monkeypatch):
    """A successful search with records must not crash with
    "'NoneType' object can't be awaited" -- _process_intelx_results is
    synchronous and must be called without `await`.
    """
    monkeypatch.setattr(
        "farsight.modules.threat_intel.is_api_configured", lambda provider: True
    )

    handler = MagicMock()
    handler.post = AsyncMock(return_value={"id": "search-id-123"})
    handler.get = AsyncMock(
        return_value={
            "records": [
                {
                    "bucket": "pastes",
                    "name": "Example Paste",
                    "date": "2026-07-13T00:50:45.484249Z",
                    "snippet": "leaked content",
                }
            ]
        }
    )

    api_manager = MagicMock()
    api_manager.get_handler = MagicMock(return_value=handler)

    threat_intel = ThreatIntel(api_manager=api_manager)

    await threat_intel._check_intelx("example.com", None)

    assert len(threat_intel.results["leaks"]) == 1
    assert threat_intel.results["leaks"][0]["date"] == "2026-07-13"
