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


async def capture_domain(domain: str, timeout: float = 10.0) -> bytes:
    """Screenshot a domain, trying http then https, with an in-memory cache.

    Cache is a simple bounded dict keyed by domain -- a session-lifetime
    demo aid, not a correctness-critical cache. Raises the last exception
    if neither protocol loads within the timeout.
    """
    if domain in _cache:
        return _cache[domain]

    last_error: Optional[Exception] = None
    for protocol in ("http", "https"):
        try:
            image = await capture(f"{protocol}://{domain}", timeout=timeout)
            _store_in_cache(domain, image)
            return image
        except Exception as e:
            last_error = e
            continue

    assert last_error is not None
    raise last_error


def _store_in_cache(domain: str, image: bytes) -> None:
    if len(_cache) >= _CACHE_MAX_ENTRIES:
        oldest_key = next(iter(_cache))
        del _cache[oldest_key]
    _cache[domain] = image
