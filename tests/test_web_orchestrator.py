"""Tests for farsight.web.orchestrator.

Focuses on the property that matters most for a live demo: a single
module failing must not abort the rest of the scan, and the final
report must only claim the modules that actually succeeded.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from farsight.web.events import EventType
from farsight.web.orchestrator import run_scan_with_events


def _async_ctx(return_value):
    """Build a MagicMock usable as `async with X() as y: ...` returning
    `return_value` from `y`, matching the module classes' own pattern."""
    instance = MagicMock()
    instance.__aenter__ = AsyncMock(return_value=instance)
    instance.__aexit__ = AsyncMock(return_value=False)
    return instance, return_value


ORG_RESULT = {
    "whois": {"emails": ["admin@example.com"]},
    "total_related_domains": 2,
    "total_subdomains": 3,
}
RECON_RESULT = {
    "total_subdomains": 3,
    "port_scan": {"total_open_ports": 4},
    "email_security": {"spf": {"found": True}, "dmarc": {"found": False}},
}
THREAT_RESULT = {
    "total_leaks": 0,
    "total_dark_web": 0,
    "total_credentials": 0,
    "total_emails_found": 1,
}
TYPOSQUAT_RESULT = {
    "total_generated": 20,
    "total_active": 2,
    "typosquats": [{"domain": "examp1e.com", "risk_score": 80}],
}
NEWS_RESULT = {"total_articles": 5, "days_monitored": 30}


def _collector():
    events = []

    async def emit(event):
        events.append(event)

    return events, emit


def _patch_all_modules(monkeypatch):
    org_instance, _ = _async_ctx(None)
    org_instance.discover = AsyncMock(return_value=ORG_RESULT)
    monkeypatch.setattr(
        "farsight.web.orchestrator.OrgDiscovery", MagicMock(return_value=org_instance)
    )

    recon_instance = MagicMock()
    recon_instance.scan = AsyncMock(return_value=RECON_RESULT)
    monkeypatch.setattr(
        "farsight.web.orchestrator.Recon", MagicMock(return_value=recon_instance)
    )

    threat_instance, _ = _async_ctx(None)
    threat_instance.gather_intelligence = AsyncMock(return_value=THREAT_RESULT)
    monkeypatch.setattr(
        "farsight.web.orchestrator.ThreatIntel",
        MagicMock(return_value=threat_instance),
    )

    typosquat_instance, _ = _async_ctx(None)
    typosquat_instance.detect = AsyncMock(return_value=TYPOSQUAT_RESULT)
    monkeypatch.setattr(
        "farsight.web.orchestrator.TyposquatDetector",
        MagicMock(return_value=typosquat_instance),
    )

    news_instance, _ = _async_ctx(None)
    news_instance.monitor = AsyncMock(return_value=NEWS_RESULT)
    monkeypatch.setattr(
        "farsight.web.orchestrator.NewsMonitor", MagicMock(return_value=news_instance)
    )

    return {
        "org": org_instance,
        "recon": recon_instance,
        "threat": threat_instance,
        "typosquat": typosquat_instance,
        "news": news_instance,
    }


@pytest.fixture
def mock_report_writer(monkeypatch):
    writer = MagicMock()
    writer.generate_report = MagicMock(return_value=Path("report.md"))
    writer.convert_to_pdf = MagicMock(return_value=Path("report.pdf"))
    monkeypatch.setattr(
        "farsight.web.orchestrator.ReportWriter", MagicMock(return_value=writer)
    )
    return writer


@pytest.mark.asyncio
async def test_full_scan_emits_expected_event_sequence(monkeypatch, mock_report_writer):
    _patch_all_modules(monkeypatch)
    events, emit = _collector()

    await run_scan_with_events(
        "example.com", 1, ["org", "recon", "threat", "typosquat", "news"], emit
    )

    types = [e.type for e in events]
    assert types == [
        EventType.SCAN_STARTED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.REPORT_READY,
        EventType.SCAN_COMPLETED,
    ]
    modules_in_order = [e.module for e in events if e.module]
    assert modules_in_order == [
        "org",
        "org",
        "recon",
        "recon",
        "threat",
        "threat",
        "typosquat",
        "typosquat",
        "news",
        "news",
    ]


@pytest.mark.asyncio
async def test_emails_extracted_from_org_and_passed_to_threat_intel(
    monkeypatch, mock_report_writer
):
    mocks = _patch_all_modules(monkeypatch)
    _, emit = _collector()

    await run_scan_with_events("example.com", 1, ["org", "threat"], emit)

    mocks["threat"].gather_intelligence.assert_awaited_once_with(
        "example.com", ["admin@example.com"], 1
    )


@pytest.mark.asyncio
async def test_module_failure_does_not_abort_remaining_modules(
    monkeypatch, mock_report_writer
):
    mocks = _patch_all_modules(monkeypatch)
    mocks["org"].discover = AsyncMock(side_effect=RuntimeError("crt.sh unreachable"))
    events, emit = _collector()

    results = await run_scan_with_events(
        "example.com", 1, ["org", "recon", "threat", "typosquat", "news"], emit
    )

    error_events = [e for e in events if e.type == EventType.MODULE_ERROR]
    assert len(error_events) == 1
    assert error_events[0].module == "org"
    assert "crt.sh unreachable" in error_events[0].message

    completed_modules = [
        e.module for e in events if e.type == EventType.MODULE_COMPLETED
    ]
    assert completed_modules == ["recon", "threat", "typosquat", "news"]
    assert "org" not in results
    assert set(results.keys()) == {"recon", "threat", "typosquat", "news"}

    scan_completed = [e for e in events if e.type == EventType.SCAN_COMPLETED][0]
    assert scan_completed.data["failed_modules"] == ["org"]


@pytest.mark.asyncio
async def test_report_generated_with_only_succeeded_modules(
    monkeypatch, mock_report_writer
):
    mocks = _patch_all_modules(monkeypatch)
    mocks["threat"].gather_intelligence = AsyncMock(side_effect=RuntimeError("timeout"))
    _, emit = _collector()

    await run_scan_with_events(
        "example.com", 1, ["org", "recon", "threat", "typosquat", "news"], emit
    )

    _, kwargs = mock_report_writer.generate_report.call_args
    assert set(kwargs["modules"]) == {"org", "recon", "typosquat", "news"}
    assert set(kwargs["results"].keys()) == {"org", "recon", "typosquat", "news"}


@pytest.mark.asyncio
async def test_news_import_error_produces_placeholder_not_error(
    monkeypatch, mock_report_writer
):
    mocks = _patch_all_modules(monkeypatch)
    mocks["news"].monitor = AsyncMock(side_effect=ImportError("gnews not installed"))
    events, emit = _collector()

    results = await run_scan_with_events("example.com", 1, ["news"], emit)

    assert results["news"] == {
        "error": "gnews not installed",
        "articles": [],
        "total_articles": 0,
    }
    news_events = [e for e in events if e.module == "news"]
    assert [e.type for e in news_events] == [
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
    ]
