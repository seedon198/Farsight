"""Tests for farsight.web.scan_manager.

The single-scan-at-a-time lock exists specifically to avoid two
concurrent scans racing on farsight.config.DEFAULT_CONFIG (a shared
global mutated per-scan) — these tests exercise that guarantee.
"""

import asyncio

import pytest

from farsight.web.scan_manager import ScanManager


@pytest.mark.asyncio
async def test_try_start_succeeds_when_idle():
    manager = ScanManager()
    assert await manager.try_start() is True


@pytest.mark.asyncio
async def test_second_concurrent_try_start_is_rejected():
    manager = ScanManager()
    assert await manager.try_start() is True
    assert await manager.try_start() is False


@pytest.mark.asyncio
async def test_finish_releases_the_slot_for_the_next_scan():
    manager = ScanManager()
    await manager.try_start()
    await manager.finish()
    assert await manager.try_start() is True


@pytest.mark.asyncio
async def test_concurrent_try_start_calls_only_one_wins():
    manager = ScanManager()
    results = await asyncio.gather(*(manager.try_start() for _ in range(10)))
    assert results.count(True) == 1
    assert results.count(False) == 9


def test_register_report_returns_retrievable_id(tmp_path):
    manager = ScanManager()
    md = tmp_path / "report.md"
    pdf = tmp_path / "report.pdf"

    report_id = manager.register_report(md, pdf)

    report = manager.get_report(report_id)
    assert report == {"md": md, "pdf": pdf}


def test_get_report_unknown_id_returns_none():
    manager = ScanManager()
    assert manager.get_report("does-not-exist") is None


def test_register_report_without_pdf_defaults_to_none(tmp_path):
    manager = ScanManager()
    md = tmp_path / "report.md"

    report_id = manager.register_report(md)

    assert manager.get_report(report_id)["pdf"] is None
