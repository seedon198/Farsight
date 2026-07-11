"""Tests for farsight.web.replay.

The property that matters: replay must emit the exact same event
shape run_scan_with_events() does, so the frontend can't tell (and
doesn't need to know) whether it's watching a live scan or a replayed
fixture. A malformed fixture must degrade to SCAN_FAILED, not crash
the WebSocket mid-presentation.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from farsight.web.events import EventType
from farsight.web.replay import replay_scan


def _write_fixture(tmp_path: Path, domain="example.com", depth=1, results=None) -> Path:
    fixture = {
        "domain": domain,
        "depth": depth,
        "results": (
            results
            if results is not None
            else {
                "org": {"total_related_domains": 2, "total_subdomains": 3, "whois": {}},
                "typosquat": {
                    "total_generated": 20,
                    "total_active": 1,
                    "typosquats": [{"domain": "examp1e.com", "risk_score": 80}],
                },
            }
        ),
    }
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _collector():
    events = []

    async def emit(event):
        events.append(event)

    return events, emit


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
async def test_replay_emits_same_event_shape_as_live_scan(tmp_path, mock_report_writer):
    fixture_path = _write_fixture(tmp_path)
    events, emit = _collector()

    await replay_scan(fixture_path, emit, pacing_seconds=0)

    types = [e.type for e in events]
    assert types == [
        EventType.SCAN_STARTED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.MODULE_STARTED,
        EventType.MODULE_COMPLETED,
        EventType.REPORT_READY,
        EventType.SCAN_COMPLETED,
    ]


@pytest.mark.asyncio
async def test_replay_follows_module_order_regardless_of_fixture_key_order(
    tmp_path, mock_report_writer
):
    # typosquat listed before org in the fixture dict; MODULE_ORDER must win.
    results = {
        "typosquat": {"total_generated": 1, "total_active": 0, "typosquats": []},
        "org": {"total_related_domains": 0, "total_subdomains": 0, "whois": {}},
    }
    fixture_path = _write_fixture(tmp_path, results=results)
    events, emit = _collector()

    await replay_scan(fixture_path, emit, pacing_seconds=0)

    modules_in_order = [e.module for e in events if e.module]
    assert modules_in_order == ["org", "org", "typosquat", "typosquat"]


@pytest.mark.asyncio
async def test_replay_marks_events_as_replay(tmp_path, mock_report_writer):
    fixture_path = _write_fixture(tmp_path)
    events, emit = _collector()

    await replay_scan(fixture_path, emit, pacing_seconds=0)

    started = [e for e in events if e.type == EventType.SCAN_STARTED][0]
    completed = [e for e in events if e.type == EventType.SCAN_COMPLETED][0]
    assert started.data["replay"] is True
    assert completed.data["replay"] is True


@pytest.mark.asyncio
async def test_replay_paces_between_module_events(
    tmp_path, mock_report_writer, monkeypatch
):
    fixture_path = _write_fixture(tmp_path)
    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr("farsight.web.replay.asyncio.sleep", fake_sleep)

    _, emit = _collector()
    await replay_scan(fixture_path, emit, pacing_seconds=2.5)

    assert sleep_calls == [2.5, 2.5]  # once per module in the fixture


@pytest.mark.asyncio
async def test_replay_malformed_fixture_emits_scan_failed_not_exception(tmp_path):
    bad_path = tmp_path / "corrupt.json"
    bad_path.write_text("{not valid json", encoding="utf-8")
    events, emit = _collector()

    result = await replay_scan(bad_path, emit, pacing_seconds=0)

    assert result == {}
    assert [e.type for e in events] == [EventType.SCAN_FAILED]


@pytest.mark.asyncio
async def test_replay_missing_fixture_file_emits_scan_failed(tmp_path):
    missing_path = tmp_path / "does-not-exist.json"
    events, emit = _collector()

    await replay_scan(missing_path, emit, pacing_seconds=0)

    assert [e.type for e in events] == [EventType.SCAN_FAILED]
