"""Extended attack surface discovery module for FARSIGHT.

Certificate transparency (org_discovery.py) only surfaces assets that carry
a public cert with a hostname matching the target domain. This module finds
company-owned assets that never show up that way: raw IPs and netblocks
identified by ASN/org ownership instead of hostname, cloud-hosted resources
(AWS/Azure/GCP) tagged by IP range rather than DNS, and exposed object
storage buckets. False positives are expected and acceptable here -- the
goal is coverage, not precision.
"""

import asyncio
import base64
import ipaddress
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set

import aiohttp

from farsight.utils.common import logger
from farsight.utils.api_handler import APIManager
from farsight.utils import cloud_ranges
from farsight.config import get_config, is_api_configured

_BGPVIEW_BASE = "https://api.bgpview.io"
_HE_SEARCH_URL = "https://bgp.he.net/search?search%5Bsearch%5D={query}&commit=Search"
_HE_ASN_URL = "https://bgp.he.net/AS{asn}"
_RIPESTAT_BASE = "https://stat.ripe.net/data"

# bgp.he.net's search results page mixes Domain/TLD/ASN/prefix result
# types in one table; this only matches rows explicitly typed "ASN".
_HE_ASN_SEARCH_RE = re.compile(
    r'<a href="/AS(\d+)">AS\d+</a></td><td>ASN</td>\s*<td>([^<]+)', re.S
)
# Matches both the IPv4 and IPv6 prefix tables on an AS detail page --
# both use the same "/net/<cidr>" link shape.
_HE_PREFIX_RE = re.compile(
    r'<a href="/net/([0-9a-fA-F:./]+)">[0-9a-fA-F:./]+</a>\s*</td>\s*<td>([^<]+)', re.S
)

# Safety valve, not a user-facing setting: even a false-positive-tolerant
# ASN name search can return dozens of matches for a common word, and each
# one costs a bgp.he.net scrape for its prefix list. Cap how many distinct
# ASNs get their netblocks fetched per scan.
_MAX_ASNS_FOR_PREFIX_LOOKUP = 15


class AttackSurface:
    """Extended attack surface discovery: org/keyword-based asset discovery
    for infrastructure certificate transparency alone won't surface."""

    def __init__(self, api_manager: Optional[APIManager] = None):
        """
        Initialize attack surface module.

        Args:
            api_manager: API manager for making API requests (optional)
        """
        self.api_manager = api_manager or APIManager()
        self.session: Optional[aiohttp.ClientSession] = None
        self._ripestat_semaphore = asyncio.Semaphore(8)
        self.results = self._empty_results()

    @staticmethod
    def _empty_results() -> Dict[str, Any]:
        return {
            "asns": [],
            "netblocks": [],
            "shodan_org_results": [],
            "exposed_buckets": [],
            "fullhunt_hosts": [],
            "netlas_hosts": [],
            "zoomeye_hosts": [],
            "onyphe_hosts": [],
            "tagged_known_ips": [],
        }

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=get_config("timeout", 30))
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def discover(
        self,
        domain: str,
        org_name: Optional[str] = None,
        subsidiaries: Optional[List[Dict[str, Any]]] = None,
        known_ips: Optional[List[str]] = None,
        depth: int = 1,
    ) -> Dict[str, Any]:
        """
        Discover extended attack surface: ASNs/netblocks, cloud-hosted
        assets, and exposed storage buckets tied to the target org.

        Args:
            domain: Target domain
            org_name: Organization name (falls back to a domain-derived
                guess if not provided)
            subsidiaries: Acquisitions list from OrgDiscovery.discover(),
                used as extra query keywords alongside the primary org name
            known_ips: IPs already discovered elsewhere in the scan (e.g.
                recon.py's DNS resolution), tagged against cloud IP ranges
                in addition to netblocks this module finds itself
            depth: Scan depth level (1-3). Keyless ASN/netblock/cloud-range
                work always runs; keyed provider lookups need depth >= 2

        Returns:
            Dictionary with discovery results
        """
        self.results = self._empty_results()

        keywords = self._build_keyword_list(domain, org_name, subsidiaries)
        known_ips = known_ips or []

        await self._discover_asns_and_netblocks(keywords)

        ranges = await cloud_ranges.load_ranges(self.session)
        self._tag_netblocks(ranges)
        cloud_summary = self._tag_known_ips(known_ips, ranges)

        if depth >= 2:
            tasks = []
            for keyword in keywords:
                for check in (
                    self._check_and_run_shodan_org,
                    self._check_and_run_shodan_keyword,
                    self._check_and_run_grayhatwarfare,
                    self._check_and_run_fullhunt,
                    self._check_and_run_netlas,
                    self._check_and_run_zoomeye,
                    self._check_and_run_onyphe,
                ):
                    task = check(keyword)
                    if task:
                        tasks.append(task)
            if tasks:
                await asyncio.gather(*tasks)

        return {
            "target": domain,
            "keywords_used": keywords,
            "asns": self.results["asns"],
            "total_asns": len(self.results["asns"]),
            "netblocks": self.results["netblocks"],
            "total_netblocks": len(self.results["netblocks"]),
            "shodan_org_results": self.results["shodan_org_results"],
            "total_shodan_org_results": sum(
                r.get("total_results", 0) for r in self.results["shodan_org_results"]
            ),
            "exposed_buckets": self.results["exposed_buckets"],
            "total_exposed_buckets": len(self.results["exposed_buckets"]),
            "fullhunt_hosts": self.results["fullhunt_hosts"],
            "total_fullhunt_hosts": len(self.results["fullhunt_hosts"]),
            "netlas_hosts": self.results["netlas_hosts"],
            "total_netlas_hosts": len(self.results["netlas_hosts"]),
            "zoomeye_hosts": self.results["zoomeye_hosts"],
            "total_zoomeye_hosts": len(self.results["zoomeye_hosts"]),
            "onyphe_hosts": self.results["onyphe_hosts"],
            "total_onyphe_hosts": len(self.results["onyphe_hosts"]),
            "tagged_known_ips": self.results["tagged_known_ips"],
            "cloud_summary": cloud_summary,
        }

    def _build_keyword_list(
        self,
        domain: str,
        org_name: Optional[str],
        subsidiaries: Optional[List[Dict[str, Any]]],
    ) -> List[str]:
        """Build the org/subsidiary name keyword list to query, capped by
        attack_surface_max_keywords so a long acquisition history doesn't
        blow through free-tier query budgets."""
        max_keywords = get_config("attack_surface_max_keywords", 5)
        primary = (org_name or domain.split(".")[0]).strip()

        keywords = [primary]
        seen = {primary.lower()}

        for sub in subsidiaries or []:
            if len(keywords) >= max_keywords:
                break
            name = (sub.get("org_name") or "").strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            keywords.append(name)

        return keywords

    # -- Phase 1: keyless ASN / netblock / cloud-range discovery --

    async def _discover_asns_and_netblocks(self, keywords: List[str]) -> None:
        seen_asns: Set[str] = set()

        for keyword in keywords:
            try:
                matches = await self._search_asn_by_name(keyword)
            except Exception as e:
                logger.warning(f"ASN search failed for '{keyword}': {str(e)}")
                matches = []

            for match in matches:
                if match["asn"] in seen_asns:
                    continue
                seen_asns.add(match["asn"])
                self.results["asns"].append(match)

        if not seen_asns:
            return

        lookup_asns = list(seen_asns)[:_MAX_ASNS_FOR_PREFIX_LOOKUP]
        await asyncio.gather(*(self._get_asn_netblocks(asn) for asn in lookup_asns))
        await asyncio.gather(*(self._enrich_asn_ripestat(asn) for asn in lookup_asns))

    async def _search_asn_by_name(self, keyword: str) -> List[Dict[str, Any]]:
        """Look up ASNs by organization name via BGPView, falling back to
        scraping bgp.he.net's search page if BGPView is unreachable."""
        try:
            async with self.session.get(
                f"{_BGPVIEW_BASE}/search", params={"query_term": keyword}
            ) as response:
                if response.status == 200:
                    data = await response.json(content_type=None)
                    asns = (data.get("data") or {}).get("asns") or []
                    if asns:
                        return [
                            {
                                "asn": str(a["asn"]),
                                "name": a.get("name"),
                                "description": a.get("description"),
                                "country_code": a.get("country_code"),
                                "matched_keyword": keyword,
                                "source": "bgpview",
                            }
                            for a in asns
                            if a.get("asn")
                        ]
        except Exception as e:
            logger.info(f"BGPView search unavailable for '{keyword}': {str(e)}")

        return await self._search_asn_by_name_he(keyword)

    async def _search_asn_by_name_he(self, keyword: str) -> List[Dict[str, Any]]:
        """Fallback ASN-by-name search via bgp.he.net, same 'scrape a page
        for current data' pattern org_discovery.py already uses for
        RapidDNS/DNSDB."""
        try:
            url = _HE_SEARCH_URL.format(query=urllib.parse.quote(keyword))
            async with self.session.get(
                url, headers={"User-Agent": get_config("user_agent")}
            ) as response:
                if response.status != 200:
                    return []
                html = await response.text()
        except Exception as e:
            logger.warning(f"bgp.he.net search failed for '{keyword}': {str(e)}")
            return []

        return [
            {
                "asn": asn_number,
                "name": None,
                "description": description.strip(),
                "country_code": None,
                "matched_keyword": keyword,
                "source": "bgp.he.net",
            }
            for asn_number, description in _HE_ASN_SEARCH_RE.findall(html)
        ]

    async def _get_asn_netblocks(self, asn: str) -> None:
        try:
            async with self.session.get(
                f"{_BGPVIEW_BASE}/asn/{asn}/prefixes"
            ) as response:
                if response.status == 200:
                    data = await response.json(content_type=None)
                    prefix_data = data.get("data") or {}
                    prefixes = (prefix_data.get("ipv4_prefixes") or []) + (
                        prefix_data.get("ipv6_prefixes") or []
                    )
                    if prefixes:
                        for p in prefixes:
                            cidr = p.get("prefix")
                            if not cidr:
                                continue
                            self.results["netblocks"].append(
                                {
                                    "cidr": cidr,
                                    "asn": asn,
                                    "description": p.get("description")
                                    or p.get("name"),
                                    "country_code": p.get("country_code"),
                                    "source": "bgpview",
                                }
                            )
                        return
        except Exception as e:
            logger.info(f"BGPView prefixes unavailable for AS{asn}: {str(e)}")

        await self._get_asn_netblocks_he(asn)

    async def _get_asn_netblocks_he(self, asn: str) -> None:
        try:
            url = _HE_ASN_URL.format(asn=asn)
            async with self.session.get(
                url, headers={"User-Agent": get_config("user_agent")}
            ) as response:
                if response.status != 200:
                    return
                html = await response.text()
        except Exception as e:
            logger.warning(f"bgp.he.net prefixes fetch failed for AS{asn}: {str(e)}")
            return

        for cidr, description in _HE_PREFIX_RE.findall(html):
            self.results["netblocks"].append(
                {
                    "cidr": cidr,
                    "asn": asn,
                    "description": description.strip(),
                    "country_code": None,
                    "source": "bgp.he.net",
                }
            )

    async def _enrich_asn_ripestat(self, asn: str) -> None:
        """Best-effort holder-name enrichment via RIPEstat (better coverage
        in the RIPE/EU region than BGPView/bgp.he.net descriptions)."""
        try:
            async with self._ripestat_semaphore:
                async with self.session.get(
                    f"{_RIPESTAT_BASE}/as-overview/data.json",
                    params={"resource": f"AS{asn}"},
                    headers={"User-Agent": get_config("user_agent")},
                ) as response:
                    if response.status != 200:
                        return
                    payload = await response.json(content_type=None)
        except Exception as e:
            logger.info(f"RIPEstat enrichment failed for AS{asn}: {str(e)}")
            return

        holder = (payload.get("data") or {}).get("holder")
        if not holder:
            return

        for entry in self.results["asns"]:
            if entry["asn"] == asn:
                entry.setdefault("ripestat_holder", holder)

    def _tag_netblocks(self, ranges: Dict[str, List[Dict[str, Any]]]) -> None:
        for netblock in self.results["netblocks"]:
            cidr = netblock.get("cidr")
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            tag = cloud_ranges.tag_ip(str(network.network_address), ranges)
            if tag:
                netblock["cloud"] = tag

    def _tag_known_ips(
        self, known_ips: List[str], ranges: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, int]:
        counts = {"aws": 0, "azure": 0, "gcp": 0}

        for ip in set(known_ips):
            tag = cloud_ranges.tag_ip(ip, ranges)
            if tag:
                counts[tag["provider"]] += 1
                self.results["tagged_known_ips"].append({"ip": ip, **tag})

        for netblock in self.results["netblocks"]:
            cloud = netblock.get("cloud")
            if cloud:
                counts[cloud["provider"]] += 1

        return counts

    # -- Phase 2: keyed providers (Shodan extended usage + new sources) --

    def _check_and_run_shodan_org(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("shodan"):
            return asyncio.create_task(self._query_shodan_org(keyword))
        return None

    async def _query_shodan_org(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("shodan")
            response = await handler.get(
                "shodan/host/search", params={"query": f'org:"{keyword}"'}
            )
            hosts = self._parse_shodan_hosts(response)
            if hosts:
                self.results["shodan_org_results"].append(
                    {
                        "query_type": "org",
                        "keyword": keyword,
                        "total_results": response.get("total", 0),
                        "hosts": hosts,
                    }
                )
        except Exception as e:
            logger.warning(f"Shodan org search failed for '{keyword}': {str(e)}")

    def _check_and_run_shodan_keyword(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("shodan"):
            return asyncio.create_task(self._query_shodan_keyword(keyword))
        return None

    async def _query_shodan_keyword(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("shodan")
            response = await handler.get(
                "shodan/host/search", params={"query": keyword}
            )
            hosts = self._parse_shodan_hosts(response)
            if hosts:
                self.results["shodan_org_results"].append(
                    {
                        "query_type": "keyword",
                        "keyword": keyword,
                        "total_results": response.get("total", 0),
                        "hosts": hosts,
                    }
                )
        except Exception as e:
            logger.warning(f"Shodan keyword search failed for '{keyword}': {str(e)}")

    @staticmethod
    def _parse_shodan_hosts(
        response: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not response or "matches" not in response:
            return []
        hosts = []
        for host in response["matches"]:
            host_info = {
                "ip": host.get("ip_str"),
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "org": host.get("org"),
                "timestamp": host.get("timestamp"),
            }
            if "data" in host:
                host_info["banner"] = host["data"][:200]
            hosts.append(host_info)
        return hosts

    def _check_and_run_grayhatwarfare(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("grayhatwarfare"):
            return asyncio.create_task(self._query_grayhatwarfare(keyword))
        return None

    async def _query_grayhatwarfare(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("grayhatwarfare")
            response = await handler.get(
                "buckets", params={"keywords": keyword, "limit": 20}
            )
            for bucket in (response or {}).get("buckets", []) or []:
                self.results["exposed_buckets"].append(
                    {
                        "bucket": bucket.get("bucket"),
                        "type": bucket.get("type"),
                        "file_count": bucket.get("fileCount"),
                        "matched_keyword": keyword,
                        "source": "grayhatwarfare",
                    }
                )
        except Exception as e:
            logger.warning(f"GrayHatWarfare search failed for '{keyword}': {str(e)}")

    def _check_and_run_fullhunt(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("fullhunt"):
            return asyncio.create_task(self._query_fullhunt(keyword))
        return None

    async def _query_fullhunt(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("fullhunt")
            response = await handler.post(
                "global/search", data={"organization": keyword}
            )
            hosts = (response or {}).get("results") or (response or {}).get(
                "hosts"
            ) or []
            for host in hosts:
                self.results["fullhunt_hosts"].append(
                    {
                        "host": host.get("host") or host.get("domain"),
                        "ip": host.get("ip_address"),
                        "is_cloud": host.get("is_cloud"),
                        "matched_keyword": keyword,
                        "source": "fullhunt",
                    }
                )
        except Exception as e:
            logger.warning(f"FullHunt search failed for '{keyword}': {str(e)}")

    def _check_and_run_netlas(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("netlas"):
            return asyncio.create_task(self._query_netlas(keyword))
        return None

    async def _query_netlas(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("netlas")
            response = await handler.get(
                "responses/", params={"q": f'organization:"{keyword}"'}
            )
            for item in (response or {}).get("items", []) or []:
                data = item.get("data", item) if isinstance(item, dict) else {}
                self.results["netlas_hosts"].append(
                    {
                        "ip": data.get("ip"),
                        "port": data.get("port"),
                        "host": data.get("host"),
                        "matched_keyword": keyword,
                        "source": "netlas",
                    }
                )
        except Exception as e:
            logger.warning(f"Netlas search failed for '{keyword}': {str(e)}")

    def _check_and_run_zoomeye(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("zoomeye"):
            return asyncio.create_task(self._query_zoomeye(keyword))
        return None

    async def _query_zoomeye(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("zoomeye")
            query = base64.b64encode(f'org:"{keyword}"'.encode()).decode()
            response = await handler.post(
                "search", data={"qbase64": query, "page": 1}
            )
            for item in (response or {}).get("data", []) or []:
                if not isinstance(item, dict):
                    continue
                self.results["zoomeye_hosts"].append(
                    {
                        "ip": item.get("ip"),
                        "port": item.get("port"),
                        "domain": item.get("domain"),
                        "matched_keyword": keyword,
                        "source": "zoomeye",
                    }
                )
        except Exception as e:
            logger.warning(f"ZoomEye search failed for '{keyword}': {str(e)}")

    def _check_and_run_onyphe(self, keyword: str) -> Optional[asyncio.Task]:
        if is_api_configured("onyphe"):
            return asyncio.create_task(self._query_onyphe(keyword))
        return None

    async def _query_onyphe(self, keyword: str) -> None:
        try:
            handler = self.api_manager.get_handler("onyphe")
            response = await handler.get(
                "search/", params={"q": f'organization:"{keyword}"'}
            )
            for item in (response or {}).get("results", []) or []:
                self.results["onyphe_hosts"].append(
                    {
                        "ip": item.get("ip"),
                        "organization": item.get("organization"),
                        "asn": item.get("asn"),
                        "matched_keyword": keyword,
                        "source": "onyphe",
                    }
                )
        except Exception as e:
            logger.warning(f"Onyphe search failed for '{keyword}': {str(e)}")
