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
        "<body>illustrative documents literature coordination</body></html>"
    )

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    detector.session = MagicMock()
    detector.session.get = MagicMock(return_value=mock_ctx)

    # Content similarity is measured against the real target's vocabulary,
    # captured by detect() before candidates are analysed.
    detector._target_fingerprint = detector._page_tokens(
        "<html><body>illustrative documents literature coordination</body></html>"
    )

    result = await detector._check_domain_http("example.com")

    assert result["status"] == 200
    assert result["title"] == "Example Domain"
    assert result["content_size"] > 0
    # This page reproduces the target's whole vocabulary, so it reads as a
    # near-clone rather than an unrelated site that shares a similar name.
    assert result["content_similarity"] == 100


@pytest.mark.asyncio
async def test_check_domain_http_no_session_returns_default():
    detector = TyposquatDetector()
    detector.session = None
    result = await detector._check_domain_http("example.com")
    assert result["status"] == 0
    assert result["title"] is None


@pytest.mark.asyncio
async def test_content_similarity_distinguishes_impostor_from_unrelated_site():
    """The signal that matters is whether a lookalike reproduces the real
    site's wording -- not merely that its name resembles the target. A
    hardcoded keyword list scored every non-Sony target at zero, so an
    unrelated business and a genuine clone were indistinguishable.
    """
    detector = TyposquatDetector()
    detector._target_fingerprint = detector._page_tokens(
        "<html><title>Example Domain</title><body>This domain is for use in "
        "illustrative examples in documents.</body></html>"
    )

    clone = "<html><body>illustrative examples in documents, domain use</body></html>"
    unrelated = "<html><body>pet safe disinfectant spray kills odors</body></html>"

    assert detector._content_overlap(clone) > 50
    assert detector._content_overlap(unrelated) == 0
    assert detector._content_overlap("") == 0


@pytest.mark.asyncio
async def test_content_overlap_zero_without_a_fingerprint():
    """If the real site couldn't be fetched, comparison is skipped rather
    than guessed at."""
    detector = TyposquatDetector()
    assert detector._content_overlap("<html><body>anything at all</body></html>") == 0
