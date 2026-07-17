"""Tests for farsight.utils.cloud_ranges."""

import ipaddress

from farsight.utils.cloud_ranges import tag_ip

RANGES = {
    "aws": [
        {
            "network": ipaddress.ip_network("3.5.140.0/22"),
            "region": "ap-northeast-2",
            "service": "AMAZON",
        }
    ],
    "gcp": [
        {
            "network": ipaddress.ip_network("34.1.208.0/20"),
            "region": "africa-south1",
            "service": "Google Cloud",
        }
    ],
    "azure": [
        {
            "network": ipaddress.ip_network("20.33.0.0/16"),
            "region": "eastus",
            "service": "AzureCloud",
        }
    ],
}


def test_tag_ip_matches_aws_range():
    result = tag_ip("3.5.140.10", RANGES)
    assert result == {
        "provider": "aws",
        "region": "ap-northeast-2",
        "service": "AMAZON",
    }


def test_tag_ip_matches_gcp_range():
    result = tag_ip("34.1.208.5", RANGES)
    assert result["provider"] == "gcp"


def test_tag_ip_matches_azure_range():
    result = tag_ip("20.33.1.1", RANGES)
    assert result["provider"] == "azure"


def test_tag_ip_no_match_returns_none():
    assert tag_ip("8.8.8.8", RANGES) is None


def test_tag_ip_invalid_ip_returns_none():
    assert tag_ip("not-an-ip", RANGES) is None


def test_tag_ip_empty_ranges_returns_none():
    assert tag_ip("3.5.140.10", {"aws": [], "gcp": [], "azure": []}) is None
