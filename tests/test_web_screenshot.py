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


@pytest.fixture(autouse=True)
def clear_cache():
    screenshot._cache.clear()
    yield
    screenshot._cache.clear()


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


@pytest.mark.asyncio
async def test_capture_domain_tries_http_then_https_on_failure(monkeypatch):
    calls = []

    async def fake_capture(url, timeout=10.0):
        calls.append(url)
        if url.startswith("http://"):
            raise ConnectionError("refused")
        return b"https-worked"

    monkeypatch.setattr(screenshot, "capture", fake_capture)

    result = await screenshot.capture_domain("example.com")

    assert result == b"https-worked"
    assert calls == ["http://example.com", "https://example.com"]


@pytest.mark.asyncio
async def test_capture_domain_caches_result(monkeypatch):
    call_count = 0

    async def fake_capture(url, timeout=10.0):
        nonlocal call_count
        call_count += 1
        return b"cached-bytes"

    monkeypatch.setattr(screenshot, "capture", fake_capture)

    first = await screenshot.capture_domain("example.com")
    second = await screenshot.capture_domain("example.com")

    assert first == second == b"cached-bytes"
    assert call_count == 1


@pytest.mark.asyncio
async def test_capture_domain_raises_when_both_protocols_fail(monkeypatch):
    async def fake_capture(url, timeout=10.0):
        raise ConnectionError(f"refused: {url}")

    monkeypatch.setattr(screenshot, "capture", fake_capture)

    with pytest.raises(ConnectionError):
        await screenshot.capture_domain("dead-domain.example")


@pytest.mark.asyncio
async def test_capture_domain_cache_evicts_oldest_when_full(monkeypatch):
    async def fake_capture(url, timeout=10.0):
        return f"bytes-for-{url}".encode()

    monkeypatch.setattr(screenshot, "capture", fake_capture)
    monkeypatch.setattr(screenshot, "_CACHE_MAX_ENTRIES", 2)

    await screenshot.capture_domain("first.example")
    await screenshot.capture_domain("second.example")
    await screenshot.capture_domain("third.example")

    assert "first.example" not in screenshot._cache
    assert "second.example" in screenshot._cache
    assert "third.example" in screenshot._cache
