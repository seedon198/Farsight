"""Tests for farsight.modules.org_discovery.

Covers the hostname validator and crt.sh parsing fix: previously a
`\\n` (literal backslash-n) split instead of a real newline let
multi-line certificate SAN blocks through unsplit, leaking emails and
CA metadata strings into the "related domains" report.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from farsight.modules.org_discovery import OrgDiscovery, _looks_like_hostname


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", True),
        ("www.example.com", True),
        ("*.example.com", True),
        ("dev.example.com", True),
        ("www.example.org", True),
        ("AS207960 Test Intermediate - example.com", False),
        ("user@example.com", False),
        ("subjectname@example.com", False),
        ("", False),
        ("example.com\nwww.example.com", False),
    ],
)
def test_looks_like_hostname(value, expected):
    assert _looks_like_hostname(value) is expected


@pytest.mark.asyncio
async def test_get_crt_sh_domains_filters_and_splits_correctly():
    """Realistic crt.sh payload matching what was observed live:
    multi-line name_value, an embedded email SAN, and a CA metadata
    common_name. Only genuine hostnames should survive.
    """
    fake_certs = [
        {
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\ndev.example.com",
        },
        {
            "common_name": "AS207960 Test Intermediate - example.com",
            "name_value": "example.com",
        },
        {
            "common_name": "",
            "name_value": "user@example.com\nsubjectname@example.com",
        },
        {"common_name": "www.example.org", "name_value": "www.example.org"},
    ]

    org = OrgDiscovery()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=fake_certs)

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    org.session = MagicMock()
    org.session.get = MagicMock(return_value=mock_ctx)

    await org._get_crt_sh_domains("example.com")

    assert sorted(org.results["crt_sh"]) == [
        "dev.example.com",
        "example.com",
        "www.example.com",
        "www.example.org",
    ]


@pytest.mark.asyncio
async def test_get_crt_sh_domains_handles_non_200_gracefully():
    org = OrgDiscovery()
    mock_response = AsyncMock()
    mock_response.status = 404

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    org.session = MagicMock()
    org.session.get = MagicMock(return_value=mock_ctx)

    await org._get_crt_sh_domains("example.com")

    assert org.results["crt_sh"] == []
