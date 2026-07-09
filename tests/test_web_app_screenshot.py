"""Tests for the /api/screenshot route in farsight.web.app."""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from farsight.web import screenshot
from farsight.web.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


def test_screenshot_returns_503_when_playwright_not_installed(client, monkeypatch):
    monkeypatch.setattr(screenshot, "PLAYWRIGHT_AVAILABLE", False)

    resp = client.get("/api/screenshot", params={"domain": "example.com"})

    assert resp.status_code == 503
    assert resp.json()["error"] == "playwright_not_installed"


def test_screenshot_returns_png_on_success(client, monkeypatch):
    monkeypatch.setattr(screenshot, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(
        screenshot, "capture_domain", AsyncMock(return_value=b"fake-png-bytes")
    )

    resp = client.get("/api/screenshot", params={"domain": "example.com"})

    assert resp.status_code == 200
    assert resp.content == b"fake-png-bytes"
    assert resp.headers["content-type"] == "image/png"


def test_screenshot_returns_502_when_capture_fails(client, monkeypatch):
    monkeypatch.setattr(screenshot, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(
        screenshot,
        "capture_domain",
        AsyncMock(side_effect=TimeoutError("nav timeout")),
    )

    resp = client.get("/api/screenshot", params={"domain": "dead-domain.example"})

    assert resp.status_code == 502
    assert resp.json()["error"] == "unreachable"
