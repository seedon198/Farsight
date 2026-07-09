"""Tests for farsight.web.screenshot.

Playwright is never actually launched here -- _get_browser is
monkeypatched to a fake browser/page, so these tests run without a real
Chromium binary installed (only the `playwright` pip package itself
needs to be importable).
"""

import pytest

from farsight.web import screenshot


class FakePage:
    def __init__(self, *, goto_exc=None, png=b"fake-png-bytes"):
        self.goto_exc = goto_exc
        self.png = png
        self.closed = False

    async def goto(self, url, timeout=None, wait_until=None):
        if self.goto_exc:
            raise self.goto_exc

    async def screenshot(self, type=None):
        return self.png

    async def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self, page):
        self._page = page

    async def new_page(self, viewport=None):
        return self._page


@pytest.fixture(autouse=True)
def playwright_available(monkeypatch):
    monkeypatch.setattr(screenshot, "PLAYWRIGHT_AVAILABLE", True)


@pytest.mark.asyncio
async def test_capture_returns_screenshot_bytes(monkeypatch):
    page = FakePage(png=b"hello-png")
    browser = FakeBrowser(page)

    async def fake_get_browser():
        return browser

    monkeypatch.setattr(screenshot, "_get_browser", fake_get_browser)

    result = await screenshot.capture("https://example.com")

    assert result == b"hello-png"
    assert page.closed is True


@pytest.mark.asyncio
async def test_capture_closes_page_even_on_navigation_failure(monkeypatch):
    page = FakePage(goto_exc=TimeoutError("nav timeout"))
    browser = FakeBrowser(page)

    async def fake_get_browser():
        return browser

    monkeypatch.setattr(screenshot, "_get_browser", fake_get_browser)

    with pytest.raises(TimeoutError):
        await screenshot.capture("https://dead-domain.example")

    assert page.closed is True


@pytest.mark.asyncio
async def test_capture_raises_clear_error_when_playwright_not_installed(monkeypatch):
    monkeypatch.setattr(screenshot, "PLAYWRIGHT_AVAILABLE", False)

    with pytest.raises(RuntimeError, match="requirements-screenshot.txt"):
        await screenshot.capture("https://example.com")
