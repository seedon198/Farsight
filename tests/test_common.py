"""Tests for farsight.utils.common."""

import asyncio

import pytest

from farsight.utils.common import RateLimiter, get_service_name, retry


def test_get_service_name_known_port():
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(22) == "SSH"


def test_get_service_name_unknown_port():
    assert get_service_name(65000) == "Unknown"


@pytest.mark.asyncio
async def test_rate_limiter_allows_calls_under_limit():
    limiter = RateLimiter(calls=5, period=60.0)
    # Should not block since we're well under the limit
    await asyncio.wait_for(limiter.wait(), timeout=1.0)
    assert len(limiter.timestamps) == 1


@pytest.mark.asyncio
async def test_retry_returns_result_without_retrying_on_success():
    calls = {"count": 0}

    @retry(max_retries=3, delay=0.01, backoff=1.0)
    async def flaky():
        calls["count"] += 1
        return "ok"

    result = await flaky()
    assert result == "ok"
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_retry_retries_then_succeeds():
    calls = {"count": 0}

    @retry(max_retries=3, delay=0.01, backoff=1.0)
    async def flaky():
        calls["count"] += 1
        if calls["count"] < 2:
            raise ValueError("transient")
        return "ok"

    result = await flaky()
    assert result == "ok"
    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_retry_raises_last_exception_after_exhausting_retries():
    @retry(max_retries=2, delay=0.01, backoff=1.0)
    async def always_fails():
        raise ValueError("permanent failure")

    with pytest.raises(ValueError, match="permanent failure"):
        await always_fails()
