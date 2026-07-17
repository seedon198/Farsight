"""Cloud provider IP range tagging for FARSIGHT.

Cross-references IP addresses against the public IP ranges AWS/GCP/Azure
publish for their own infrastructure, so any IP discovered elsewhere in a
scan can be labeled "hosted on AWS us-east-1" etc. without needing an API
key -- these are static files the providers publish for firewall/allowlist
purposes.

Results are cached at module level for the process lifetime: these files
are large (tens of thousands of prefixes) and change at most weekly, so
re-fetching per scan would be wasteful.
"""

import asyncio
import ipaddress
import re
from typing import Any, Dict, List, Optional, Union

import aiohttp

from farsight.utils.common import logger

AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
AZURE_DOWNLOAD_PAGE_URL = (
    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
)
# Matches the rotating ServiceTags_Public_<date>.json link Microsoft embeds
# in the download confirmation page's HTML.
_AZURE_JSON_LINK_RE = re.compile(
    r"https://download\.microsoft\.com/download/[^\"'\s]+?ServiceTags_Public_[^\"'\s]+?\.json"
)

_ranges_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None
_ranges_cache_lock = asyncio.Lock()


async def load_ranges(session: aiohttp.ClientSession) -> Dict[str, List[Dict[str, Any]]]:
    """
    Fetch (or return cached) AWS/GCP/Azure IP range data.

    Args:
        session: An open aiohttp session to fetch the range files with

    Returns:
        Dict with keys "aws", "gcp", "azure", each a list of
        {"network": ip_network, "region": str, "service": str} entries.
        Azure is an empty list if the confirmation-page scrape fails --
        this is a best-effort source, not a hard dependency.
    """
    global _ranges_cache

    if _ranges_cache is not None:
        return _ranges_cache

    async with _ranges_cache_lock:
        if _ranges_cache is not None:
            return _ranges_cache

        aws_task = _load_aws_ranges(session)
        gcp_task = _load_gcp_ranges(session)
        azure_task = _load_azure_ranges(session)

        aws, gcp, azure = await asyncio.gather(aws_task, gcp_task, azure_task)
        _ranges_cache = {"aws": aws, "gcp": gcp, "azure": azure}
        return _ranges_cache


async def _load_aws_ranges(session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    try:
        async with session.get(AWS_RANGES_URL) as response:
            if response.status != 200:
                logger.warning(f"AWS IP ranges fetch returned {response.status}")
                return []
            data = await response.json(content_type=None)

        entries = []
        for prefix in data.get("prefixes", []):
            network = _safe_ip_network(prefix.get("ip_prefix"))
            if network:
                entries.append(
                    {
                        "network": network,
                        "region": prefix.get("region"),
                        "service": prefix.get("service"),
                    }
                )
        for prefix in data.get("ipv6_prefixes", []):
            network = _safe_ip_network(prefix.get("ipv6_prefix"))
            if network:
                entries.append(
                    {
                        "network": network,
                        "region": prefix.get("region"),
                        "service": prefix.get("service"),
                    }
                )
        logger.info(f"Loaded {len(entries)} AWS IP range entries")
        return entries
    except Exception as e:
        logger.warning(f"Failed to load AWS IP ranges: {str(e)}")
        return []


async def _load_gcp_ranges(session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    try:
        async with session.get(GCP_RANGES_URL) as response:
            if response.status != 200:
                logger.warning(f"GCP IP ranges fetch returned {response.status}")
                return []
            data = await response.json(content_type=None)

        entries = []
        for prefix in data.get("prefixes", []):
            network = _safe_ip_network(
                prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
            )
            if network:
                entries.append(
                    {
                        "network": network,
                        "region": prefix.get("scope"),
                        "service": prefix.get("service"),
                    }
                )
        logger.info(f"Loaded {len(entries)} GCP IP range entries")
        return entries
    except Exception as e:
        logger.warning(f"Failed to load GCP IP ranges: {str(e)}")
        return []


async def _load_azure_ranges(session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    """Best-effort: Azure has no stable static URL, the actual JSON file is
    behind a rotating link on a download confirmation page. Silently
    returns an empty list if the page shape changes -- this source is a
    bonus, never a scan-blocking dependency."""
    try:
        async with session.get(AZURE_DOWNLOAD_PAGE_URL) as response:
            if response.status != 200:
                logger.info(
                    f"Azure download page fetch returned {response.status}; "
                    "skipping Azure IP tagging"
                )
                return []
            html = await response.text()

        match = _AZURE_JSON_LINK_RE.search(html)
        if not match:
            logger.info(
                "Could not find Azure ServiceTags JSON link on download page; "
                "skipping Azure IP tagging"
            )
            return []

        async with session.get(match.group(0)) as response:
            if response.status != 200:
                logger.info(f"Azure ServiceTags JSON fetch returned {response.status}")
                return []
            data = await response.json(content_type=None)

        entries = []
        for value in data.get("values", []):
            properties = value.get("properties", {}) or {}
            region = properties.get("region")
            service = value.get("name")
            for prefix in properties.get("addressPrefixes", []):
                network = _safe_ip_network(prefix)
                if network:
                    entries.append(
                        {"network": network, "region": region, "service": service}
                    )
        logger.info(f"Loaded {len(entries)} Azure IP range entries")
        return entries
    except Exception as e:
        logger.info(f"Failed to load Azure IP ranges (non-fatal): {str(e)}")
        return []


def _safe_ip_network(
    prefix: Optional[str],
) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    if not prefix:
        return None
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


def tag_ip(
    ip: str, ranges: Dict[str, List[Dict[str, Any]]]
) -> Optional[Dict[str, Any]]:
    """
    Check whether an IP falls within a known AWS/GCP/Azure range.

    Args:
        ip: IP address to check
        ranges: Ranges dict as returned by load_ranges()

    Returns:
        {"provider": "aws"|"gcp"|"azure", "region": str, "service": str}
        for the first matching range, or None if the IP isn't in any of
        them (or isn't a valid IP address).
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for provider in ("aws", "gcp", "azure"):
        for entry in ranges.get(provider, []):
            if address in entry["network"]:
                return {
                    "provider": provider,
                    "region": entry.get("region"),
                    "service": entry.get("service"),
                }
    return None
