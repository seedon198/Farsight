"""Headless-browser screenshot capture for the typosquat comparison UI.

Optional feature: requires `pip install -r requirements-screenshot.txt`
plus a one-time `playwright install chromium`. Everything here degrades
to a clear RuntimeError when playwright isn't installed, rather than
crashing the rest of the web UI.
"""

from typing import Dict, Optional

try:
    from playwright.async_api import async_playwright, Browser

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = None  # type: ignore[assignment,misc]

NOT_INSTALLED_HINT = (
    "playwright is not installed. Run: "
    "pip install -r requirements-screenshot.txt && playwright install chromium"
)

_VIEWPORT = {"width": 1280, "height": 800}
_CACHE_MAX_ENTRIES = 50

_browser: Optional["Browser"] = None
_playwright_ctx = None
_cache: Dict[str, bytes] = {}


async def _get_browser() -> "Browser":
    """Lazily launch and cache a single shared headless Chromium instance.

    Launching a fresh browser per capture is too slow for a one-click UI
    interaction, so this instance is kept alive for the server process's
    lifetime rather than closed after each screenshot.
    """
    global _browser, _playwright_ctx
    if _browser is None:
        _playwright_ctx = await async_playwright().start()
        _browser = await _playwright_ctx.chromium.launch(headless=True)
    return _browser


async def capture(url: str, timeout: float = 10.0) -> bytes:
    """Screenshot a single URL as PNG bytes. Raises on navigation failure."""
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError(NOT_INSTALLED_HINT)

    browser = await _get_browser()
    page = await browser.new_page(viewport=_VIEWPORT)
    try:
        await page.goto(url, timeout=timeout * 1000, wait_until="load")
        return await page.screenshot(type="png")
    finally:
        await page.close()
