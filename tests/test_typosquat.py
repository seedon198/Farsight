"""Tests for farsight.modules.typosquat."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from farsight.modules.typosquat import TyposquatDetector


def test_calculate_similarity_identical_domains_scores_100():
    detector = TyposquatDetector()
    assert detector._calculate_similarity("example.com", "example.com") == 100


def test_calculate_similarity_completely_different_scores_low():
    detector = TyposquatDetector()
    score = detector._calculate_similarity("example.com", "zzzzzzz.com")
    assert score < 50


def test_calculate_similarity_close_typo_scores_high():
    detector = TyposquatDetector()
    # single character swap - should be very similar
    score = detector._calculate_similarity("example.com", "exampl3.com")
    assert score > 70


@pytest.mark.asyncio
async def test_check_domain_http_uses_aiohttp_client_timeout():
    """Regression test: aiohttp.ClientTimeout was referenced without
    importing aiohttp, so this call always raised NameError, silently
    swallowed by a bare `except:`, and always returned zeroed-out
    results regardless of what the target actually served.
    """
    detector = TyposquatDetector()

    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(
        return_value="<html><head><title>Example Domain</title></head>"
        "<body>hello playstation fans</body></html>"
    )

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    detector.session = MagicMock()
    detector.session.get = MagicMock(return_value=mock_ctx)

    result = await detector._check_domain_http("example.com")

    assert result["status"] == 200
    assert result["title"] == "Example Domain"
    assert result["content_size"] > 0
    # "playstation" is one of the brand-impersonation keywords checked
    assert result["content_similarity"] > 0


@pytest.mark.asyncio
async def test_check_domain_http_no_session_returns_default():
    detector = TyposquatDetector()
    detector.session = None
    result = await detector._check_domain_http("example.com")
    assert result["status"] == 0
    assert result["title"] is None
