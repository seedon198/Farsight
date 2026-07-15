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
from farsight.utils import intelx_cache


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


@pytest.mark.asyncio
async def test_check_intelx_phonebook_maps_selectors_to_results(monkeypatch):
    monkeypatch.setattr(
        "farsight.modules.threat_intel.is_api_configured", lambda provider: True
    )

    handler = MagicMock()
    handler.post = AsyncMock(return_value={"id": "search-id-456"})
    handler.get = AsyncMock(
        return_value={
            "selectors": [
                {"selectortypeh": "Domain", "selectorvalue": "box.example.com"},
                {
                    "selectortypeh": "Email Address",
                    "selectorvalue": "info@example.com",
                },
            ]
        }
    )

    api_manager = MagicMock()
    api_manager.get_handler = MagicMock(return_value=handler)

    threat_intel = ThreatIntel(api_manager=api_manager)

    await threat_intel._check_intelx_phonebook("example.com")

    assert threat_intel.results["intelx_phonebook"] == [
        {"type": "Domain", "value": "box.example.com", "source": "IntelX Phonebook"},
        {
            "type": "Email Address",
            "value": "info@example.com",
            "source": "IntelX Phonebook",
        },
    ]


@pytest.mark.asyncio
async def test_gather_intelligence_gates_intelx_phonebook_to_depth_2(monkeypatch):
    monkeypatch.setattr(
        "farsight.modules.threat_intel.is_api_configured", lambda provider: True
    )

    api_manager = MagicMock()
    threat_intel = ThreatIntel(api_manager=api_manager)
    threat_intel._check_phonebook = AsyncMock()
    threat_intel._check_intelx = AsyncMock()
    threat_intel._check_intelx_phonebook = AsyncMock()

    await threat_intel.gather_intelligence("example.com", None, depth=1)
    threat_intel._check_intelx_phonebook.assert_not_called()

    await threat_intel.gather_intelligence("example.com", None, depth=2)
    threat_intel._check_intelx_phonebook.assert_called_once_with("example.com")


@pytest.mark.asyncio
async def test_check_intelx_phonebook_failure_does_not_raise(monkeypatch):
    monkeypatch.setattr(
        "farsight.modules.threat_intel.is_api_configured", lambda provider: True
    )

    handler = MagicMock()
    handler.post = AsyncMock(side_effect=RuntimeError("network error"))

    api_manager = MagicMock()
    api_manager.get_handler = MagicMock(return_value=handler)

    threat_intel = ThreatIntel(api_manager=api_manager)

    await threat_intel._check_intelx_phonebook("example.com")

    assert threat_intel.results["intelx_phonebook"] == []


@pytest.mark.asyncio
async def test_check_intelx_reuses_cached_results_for_duplicate_query(monkeypatch):
    """A second identical search must be served from the local cache
    without spending another IntelX search credit.
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
    assert handler.post.call_count == 1
    assert handler.get.call_count == 1

    # Second identical search: should be a full cache hit, no API calls.
    threat_intel.results["leaks"] = []
    await threat_intel._check_intelx("example.com", None)

    assert handler.post.call_count == 1
    assert handler.get.call_count == 1
    assert len(threat_intel.results["leaks"]) == 1


@pytest.mark.asyncio
async def test_check_intelx_reuses_search_id_without_new_credit(monkeypatch):
    """If a search ID is already cached (but results aren't fresh), a
    repeat search must reuse it against the free result endpoint instead
    of starting a new (credit-consuming) search.
    """
    monkeypatch.setattr(
        "farsight.modules.threat_intel.is_api_configured", lambda provider: True
    )

    search_params = {
        "term": "example.com",
        "maxresults": 20,
        "media": 0,
        "sort": 4,
        "terminate": [],
    }
    intelx_cache.save("intelligent/search", search_params, "cached-search-id")

    handler = MagicMock()
    handler.post = AsyncMock(return_value={"id": "should-not-be-used"})
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

    handler.post.assert_not_called()
    handler.get.assert_called_once_with(
        "intelligent/search/result?id=cached-search-id&limit=20"
    )
    assert len(threat_intel.results["leaks"]) == 1
