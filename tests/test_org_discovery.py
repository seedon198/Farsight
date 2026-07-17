"""Tests for farsight.modules.org_discovery.

Covers the hostname validator and crt.sh parsing fix: previously a
`\\n` (literal backslash-n) split instead of a real newline let
multi-line certificate SAN blocks through unsplit, leaking emails and
CA metadata strings into the "related domains" report.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from farsight.modules.org_discovery import (
    OrgDiscovery,
    _looks_like_domain_website,
    _looks_like_hostname,
)


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


# --- Acquisition discovery -------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://www.example.com/", "example.com"),
        ("example.com", "example.com"),
        ({"value": "http://sub.example.org"}, "sub.example.org"),
        ({"url": "https://www.foo.io"}, "foo.io"),
        (None, None),
        ("", None),
        ({}, None),
    ],
)
def test_looks_like_domain_website(value, expected):
    assert _looks_like_domain_website(value) == expected


def _sparql_ctx(payload):
    """Build a mocked aiohttp `session.get(...)` context manager returning
    the given SPARQL JSON payload, matching the pattern used for crt.sh."""
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=payload)

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


@pytest.mark.asyncio
async def test_get_wikidata_acquisitions_parses_both_relationship_directions():
    entity_response = {
        "results": {
            "bindings": [
                {"item": {"type": "uri", "value": "http://www.wikidata.org/entity/Q42"}}
            ]
        }
    }
    relations_response = {
        "results": {
            "bindings": [
                {
                    "relation": {"value": "acquired"},
                    "otherLabel": {"value": "Acme Corp"},
                    "website": {"value": "http://acme.com/"},
                    "start": {"value": "2020-05-01T00:00:00Z"},
                },
                {
                    "relation": {"value": "acquired_by"},
                    "otherLabel": {"value": "Big Co"},
                },
            ]
        }
    }

    org = OrgDiscovery()
    org.session = MagicMock()
    org.session.get = MagicMock(
        side_effect=[_sparql_ctx(entity_response), _sparql_ctx(relations_response)]
    )

    await org._get_wikidata_acquisitions("example.com")

    assert len(org.results["acquisitions"]) == 2
    first, second = org.results["acquisitions"]

    assert first["source"] == "wikidata"
    assert first["relationship"] == "acquired"
    assert first["org_name"] == "Acme Corp"
    assert first["domain"] == "acme.com"
    assert first["date"] == "2020-05-01"
    assert first["confidence"] == "high"

    assert second["relationship"] == "acquired_by"
    assert second["org_name"] == "Big Co"
    assert second["domain"] is None


@pytest.mark.asyncio
async def test_get_wikidata_acquisitions_skips_relations_query_when_no_entity_found():
    org = OrgDiscovery()
    org.session = MagicMock()
    org.session.get = MagicMock(
        return_value=_sparql_ctx({"results": {"bindings": []}})
    )

    await org._get_wikidata_acquisitions("example.com")

    assert org.results["acquisitions"] == []
    assert org.session.get.call_count == 1


def test_clean_acquisition_name_strips_trailing_stopwords():
    assert OrgDiscovery._clean_acquisition_name("Beta Startup For") == "Beta Startup"
    assert OrgDiscovery._clean_acquisition_name("Beta Startup Inc.") == "Beta Startup Inc"
    assert OrgDiscovery._clean_acquisition_name("Beta Startup") == "Beta Startup"


def test_build_acquisition_patterns_matches_acquired_direction():
    patterns = OrgDiscovery._build_acquisition_patterns("Acme Inc")
    text = "Acme Inc acquires Beta Startup in a deal announced today"

    matched = None
    for pattern, relationship in patterns:
        match = pattern.search(text)
        if match:
            matched = (match.group(1), relationship)
            break

    assert matched == ("Beta Startup", "acquired")


def test_build_acquisition_patterns_matches_acquired_by_direction():
    patterns = OrgDiscovery._build_acquisition_patterns("Acme Inc")
    text = "Acme Inc was acquired by Big Holdings last week"

    matched = None
    for pattern, relationship in patterns:
        match = pattern.search(text)
        if match:
            matched = (match.group(1), relationship)
            break

    assert matched == ("Big Holdings", "acquired_by")


@pytest.mark.asyncio
async def test_confirm_domain_for_org_accepts_matching_whois_org(monkeypatch):
    class FakeWhoisResult:
        org = "Beta Startup LLC"

    monkeypatch.setattr(
        "farsight.modules.org_discovery.whois.whois",
        lambda domain: FakeWhoisResult(),
    )

    org = OrgDiscovery()
    domain = await org._confirm_domain_for_org("Beta Startup")

    assert domain == "betastartup.com"


@pytest.mark.asyncio
async def test_confirm_domain_for_org_rejects_unrelated_whois_org(monkeypatch):
    class FakeWhoisResult:
        org = "Totally Unrelated Registrar Inc"

    monkeypatch.setattr(
        "farsight.modules.org_discovery.whois.whois",
        lambda domain: FakeWhoisResult(),
    )

    org = OrgDiscovery()
    domain = await org._confirm_domain_for_org("Beta Startup")

    assert domain is None


@pytest.mark.asyncio
async def test_confirm_domain_for_org_handles_whois_lookup_failure(monkeypatch):
    def _raise(domain):
        raise Exception("no whois server for this TLD")

    monkeypatch.setattr("farsight.modules.org_discovery.whois.whois", _raise)

    org = OrgDiscovery()
    domain = await org._confirm_domain_for_org("Beta Startup")

    assert domain is None


class _FakeCrunchbaseHandler:
    """Stand-in for APIHandler("crunchbase") -- only the .get/.post surface
    _query_crunchbase actually calls."""

    def __init__(self, search_response=None, autocomplete_response=None, entity_response=None):
        self.search_response = search_response if search_response is not None else {"entities": []}
        self.autocomplete_response = (
            autocomplete_response if autocomplete_response is not None else {"entities": []}
        )
        self.entity_response = entity_response if entity_response is not None else {}

    async def post(self, endpoint, data=None, params=None, headers=None):
        return self.search_response

    async def get(self, endpoint, params=None, headers=None):
        if endpoint == "autocompletes":
            return self.autocomplete_response
        return self.entity_response


@pytest.mark.asyncio
async def test_query_crunchbase_happy_path_resolves_domain_directly():
    entity_response = {
        "cards": {
            "acquiree_acquisitions": [
                {
                    "properties": {
                        "acquiree": {
                            "value": "Beta Startup",
                            "permalink": "beta-startup",
                        },
                        "acquiree_website": "https://www.betastartup.com",
                        "announced_on": "2024-01-01",
                    }
                }
            ],
            "acquirer_acquisitions": [],
        }
    }
    handler = _FakeCrunchbaseHandler(
        search_response={"entities": [{"identifier": {"permalink": "acme-inc"}}]},
        entity_response=entity_response,
    )

    org = OrgDiscovery()
    org.api_manager = MagicMock()
    org.api_manager.get_handler = MagicMock(return_value=handler)

    await org._query_crunchbase("acme.com", "Acme Inc")

    assert len(org.results["acquisitions"]) == 1
    record = org.results["acquisitions"][0]
    assert record["source"] == "crunchbase"
    assert record["relationship"] == "acquired"
    assert record["org_name"] == "Beta Startup"
    assert record["domain"] == "betastartup.com"
    assert record["confidence"] == "high"
    assert record["evidence_url"] == "https://www.crunchbase.com/organization/beta-startup"


@pytest.mark.asyncio
async def test_query_crunchbase_falls_back_to_autocomplete_when_domain_search_empty():
    handler = _FakeCrunchbaseHandler(
        search_response={"entities": []},
        autocomplete_response={"entities": [{"identifier": {"permalink": "acme-inc"}}]},
        entity_response={"cards": {}},
    )

    org = OrgDiscovery()
    org.api_manager = MagicMock()
    org.api_manager.get_handler = MagicMock(return_value=handler)

    await org._query_crunchbase("acme.com", "Acme Inc")

    # No cards in the (mocked) entity response, but the fallback path must
    # not raise and must simply yield no acquisitions.
    assert org.results["acquisitions"] == []


@pytest.mark.asyncio
async def test_query_crunchbase_skips_malformed_record_without_crashing():
    entity_response = {
        "cards": {
            "acquiree_acquisitions": [{"properties": {}}],  # missing acquiree entirely
            "acquirer_acquisitions": None,
        }
    }
    handler = _FakeCrunchbaseHandler(
        search_response={"entities": [{"identifier": {"permalink": "acme-inc"}}]},
        entity_response=entity_response,
    )

    org = OrgDiscovery()
    org.api_manager = MagicMock()
    org.api_manager.get_handler = MagicMock(return_value=handler)

    await org._query_crunchbase("acme.com", "Acme Inc")

    assert org.results["acquisitions"] == []
