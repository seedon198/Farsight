"""Organization domain discovery module for FARSIGHT.

This module discovers domains related to an organization through various
techniques including WHOIS analysis, certificate transparency logs, and
passive DNS data collection.
"""

import asyncio
import whois
import aiohttp
import re
from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup
import urllib.parse

from farsight.utils.common import logger, retry
from farsight.utils.api_handler import APIManager
from farsight.config import get_config, is_api_configured

_HOSTNAME_RE = re.compile(
    r"^(\*\.)?(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$"
)

_WIKIDATA_SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"

# Loosely matches a capitalized company-name fragment following/preceding an
# acquisition verb in free-text news copy, e.g. "Acme Corp" in "acquires Acme
# Corp for $10M". Deliberately permissive -- callers clean/verify the match.
_ACQUISITION_NAME_FRAGMENT = r"([A-Z][\w&.,'-]*(?:\s+[A-Z][\w&.,'-]*){0,4})"

# Trailing words the fragment regex sometimes over-captures (e.g. "Acme Corp
# for" from "...acquires Acme Corp for $10 million").
_ACQUISITION_TRAILING_STOPWORDS = {
    "for",
    "in",
    "a",
    "an",
    "the",
    "deal",
    "amid",
    "after",
}


def _looks_like_domain_website(value: Any) -> Optional[str]:
    """Normalize a website/URL field (str or Wikidata/Crunchbase-style dict
    with a 'value'/'url' key) down to a bare hostname, or None."""
    if isinstance(value, dict):
        value = value.get("value") or value.get("url")
    if not isinstance(value, str) or not value.strip():
        return None
    parsed = urllib.parse.urlparse(value if "//" in value else f"//{value}")
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc or None


def _looks_like_hostname(value: str) -> bool:
    """Check whether a string is plausibly a hostname (not an email, CA
    metadata string, or other certificate field masquerading as one)."""
    return bool(_HOSTNAME_RE.match(value.strip()))


class OrgDiscovery:
    """Organization domain discovery class for finding related domains."""

    def __init__(self, api_manager: Optional[APIManager] = None):
        """
        Initialize org discovery module.

        Args:
            api_manager: API manager for making API requests (optional)
        """
        self.api_manager = api_manager or APIManager()
        self.session = None
        self.results = {
            "whois": {},
            "crt_sh": [],
            "passive_dns": [],
            "api_results": [],
            "acquisitions": [],
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

    async def discover(self, domain: str, depth: int = 1) -> Dict[str, Any]:
        """
        Discover related domains and organization info.

        Args:
            domain: Target domain
            depth: Scan depth level (1-3)

        Returns:
            Dictionary with discovery results
        """
        # Reset results
        self.results = {
            "whois": {},
            "crt_sh": [],
            "passive_dns": [],
            "api_results": [],
            "acquisitions": [],
        }

        # Phase 1: WHOIS and certificate transparency don't depend on each
        # other, but the acquisition lookups below need WHOIS's org name, so
        # this phase must finish before phase 2 starts.
        await asyncio.gather(
            self._get_whois_info(domain),
            self._get_crt_sh_domains(domain),
        )

        org_name = self.results["whois"].get("org") or domain.split(".")[0].title()

        tasks = []

        # Deeper scans
        if depth >= 2:
            # Add passive DNS lookup
            tasks.append(self._get_passive_dns(domain))

            # Try API-based methods if available
            security_trails_task = self._check_and_run_security_trails(domain)
            if security_trails_task:
                tasks.append(security_trails_task)

            # Corporate acquisition lookups (free: Wikidata + news; optional
            # paid: Crunchbase) -- gated at the same depth as SecurityTrails
            # since they're all "extra API layer" lookups.
            tasks.append(self._get_wikidata_acquisitions(domain))
            tasks.append(self._get_news_acquisitions(org_name))

            crunchbase_task = self._check_and_run_crunchbase(domain, org_name)
            if crunchbase_task:
                tasks.append(crunchbase_task)

        # For maximum depth, try additional API sources
        if depth >= 3:
            censys_task = self._check_and_run_censys(domain)
            if censys_task:
                tasks.append(censys_task)

        # Run phase 2 tasks concurrently
        if tasks:
            await asyncio.gather(*tasks)

        # Process and deduplicate results
        base_domain_parts = domain.split(".")
        base_domain_suffix = ".".join(base_domain_parts[-2:])  # e.g., 'sony.com'

        # Separate domains from subdomains
        related_domains = set()
        subdomains = set([domain])  # Add original domain to subdomains

        # Process all discovered domains
        all_discovered = set()
        all_discovered.update(self.results["crt_sh"])
        all_discovered.update(self.results["passive_dns"])

        for api_result in self.results["api_results"]:
            all_discovered.update(api_result.get("domains", []))

        # Categorize as domain or subdomain
        for discovered in all_discovered:
            if discovered.endswith("." + domain):  # It's a subdomain
                subdomains.add(discovered)
            elif (
                "." + base_domain_suffix in discovered
            ):  # It's a subdomain of the main domain
                subdomains.add(discovered)
            else:  # It's a separate domain
                related_domains.add(discovered)

        # Convert to sorted lists
        sorted_domains = sorted(list(related_domains))
        sorted_subdomains = sorted(list(subdomains))

        # Final results
        return {
            "target_domain": domain,
            "whois": self.results["whois"],
            "certificate_transparency": list(self.results["crt_sh"]),
            "passive_dns": list(self.results["passive_dns"]),
            "api_results": self.results["api_results"],
            "related_domains": sorted_domains,  # Truly related domains (different TLDs)
            "discovered_subdomains": sorted_subdomains,  # Subdomains of target
            "total_related_domains": len(sorted_domains),
            "total_subdomains": len(sorted_subdomains),
            # Corporate (M&A) relationships, kept separate from related_domains:
            # these are a different legal entity, not same-owner infra.
            "acquisitions": self.results["acquisitions"],
            "total_acquisitions": len(self.results["acquisitions"]),
        }

    async def _get_whois_info(self, domain: str) -> None:
        """
        Get WHOIS information for a domain.

        Args:
            domain: Domain to query
        """
        try:
            # python-whois is synchronous, run in thread pool
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, domain)

            # Extract relevant fields
            self.results["whois"] = {
                "domain": domain,
                "registrar": whois_data.registrar,
                "creation_date": whois_data.creation_date,
                "expiration_date": whois_data.expiration_date,
                "updated_date": whois_data.updated_date,
                "name_servers": whois_data.name_servers,
                "status": whois_data.status,
                "emails": whois_data.emails,
                "org": whois_data.org,
            }

            # Clean up None values
            self.results["whois"] = {
                k: v for k, v in self.results["whois"].items() if v is not None
            }

            logger.info(f"WHOIS data retrieved for {domain}")
        except Exception as e:
            logger.error(f"Error retrieving WHOIS data for {domain}: {str(e)}")
            self.results["whois"] = {"error": str(e)}

    @retry(max_retries=3, delay=1.0, backoff=2.0)
    async def _get_crt_sh_domains(self, domain: str) -> None:
        """
        Get domains from certificate transparency logs via crt.sh.

        Args:
            domain: Domain to query
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return

        try:
            domains = await self._fetch_crt_sh(domain)
            logger.info(f"Retrieved {len(domains)} domains from crt.sh")
            self.results["crt_sh"] = list(domains)
        except Exception as e:
            logger.error(f"Error querying crt.sh: {str(e)}")

    @retry(max_retries=2, delay=1.0, backoff=2.0)
    async def _fetch_crt_sh(self, domain: str) -> set:
        """
        Fetch and parse crt.sh's certificate transparency JSON for a domain.

        Retries transient server errors (crt.sh is a shared public service
        that occasionally 502s under load). A 404 means "no matching
        certificates" per crt.sh's own API behavior, not an error, so it's
        returned as an empty result rather than retried.

        Args:
            domain: Domain to query

        Returns:
            Set of hostnames found in matching certificates
        """
        crt_sh_url = f"https://crt.sh/?q=%.{domain}&output=json"

        async with self.session.get(crt_sh_url) as response:
            if response.status == 404:
                return set()
            if response.status != 200:
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=f"crt.sh returned status {response.status}",
                )

            data = await response.json()
            domains = set()

            # Extract domains from common_name and name_value fields
            for cert in data:
                common_name = cert.get("common_name", "").strip()
                if common_name and _looks_like_hostname(common_name):
                    domains.add(common_name)

                if "name_value" in cert and cert["name_value"]:
                    # name_value is newline-delimited; a cert's SANs
                    # can include multiple hostnames per entry
                    for name in cert["name_value"].split("\n"):
                        clean_name = name.strip()
                        if _looks_like_hostname(clean_name):
                            domains.add(clean_name)

            return domains

    @retry(max_retries=2, delay=1.0, backoff=2.0)
    async def _get_passive_dns(self, domain: str) -> None:
        """
        Get domains from passive DNS data sources (RapidDNS, DNSDB.io).

        Args:
            domain: Domain to query
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return

        # Try RapidDNS first
        domains = set()
        encoded_domain = urllib.parse.quote(domain)
        rapid_dns_url = f"https://rapiddns.io/subdomain/{encoded_domain}?full=1"

        try:
            async with self.session.get(
                rapid_dns_url, headers={"User-Agent": get_config("user_agent")}
            ) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract domains from table
                    table = soup.find("table", {"class": "table"})
                    if table:
                        for row in table.find_all("tr"):
                            cells = row.find_all("td")
                            if cells and len(cells) >= 1:
                                subdomain = cells[0].text.strip()
                                # Make sure it's a subdomain of the target
                                if subdomain.endswith(domain) and "." in subdomain:
                                    domains.add(subdomain)

                    logger.info(f"Retrieved {len(domains)} domains from RapidDNS")
        except Exception as e:
            logger.error(f"Error querying RapidDNS: {str(e)}")

        # Try DNSDB.io as fallback
        try:
            dnsdb_url = f"https://dnsdb.io/search?q={encoded_domain}"

            async with self.session.get(
                dnsdb_url, headers={"User-Agent": get_config("user_agent")}
            ) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")

                    # Extract domains from DNS records
                    dns_records = soup.find_all("div", {"class": "dns-record"})
                    for record in dns_records:
                        name_elm = record.find("span", {"class": "dns-record-name"})
                        if name_elm:
                            subdomain = name_elm.text.strip()
                            if subdomain.endswith(domain) and "." in subdomain:
                                domains.add(subdomain)

                    logger.info("Retrieved additional domains from DNSDB.io")
        except Exception as e:
            logger.error(f"Error querying DNSDB.io: {str(e)}")

        self.results["passive_dns"] = list(domains)

    @retry(max_retries=2, delay=1.0, backoff=2.0)
    async def _get_wikidata_acquisitions(self, domain: str) -> None:
        """
        Find corporate acquisition relationships for the target via
        Wikidata's structured subsidiary/owned-by data (P355/P127/P749).
        Free and keyless, so this always runs at depth >= 2.

        Args:
            domain: Domain to query
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return

        try:
            entity_id = await self._find_wikidata_entity(domain)
            if not entity_id:
                return

            relations = await self._fetch_wikidata_relations(entity_id)
            for rel in relations:
                self.results["acquisitions"].append(
                    {
                        "source": "wikidata",
                        "relationship": rel["relationship"],
                        "org_name": rel["org_name"],
                        "domain": rel.get("domain"),
                        "date": rel.get("date"),
                        "evidence_url": f"https://www.wikidata.org/wiki/{entity_id}",
                        "confidence": "high",
                    }
                )

            if relations:
                logger.info(
                    f"Retrieved {len(relations)} acquisition relations from Wikidata"
                )
        except Exception as e:
            logger.error(f"Error querying Wikidata for {domain}: {str(e)}")

    async def _find_wikidata_entity(self, domain: str) -> Optional[str]:
        """
        Look up the Wikidata entity (Q-id) whose official website (P856)
        matches the target domain.

        Args:
            domain: Domain to query

        Returns:
            Wikidata Q-id, or None if no matching entity was found
        """
        query = f"""
        SELECT ?item WHERE {{
          ?item wdt:P856 ?website .
          FILTER(CONTAINS(LCASE(STR(?website)), "{domain.lower()}"))
        }} LIMIT 1
        """
        data = await self._run_sparql_query(query)
        bindings = data.get("results", {}).get("bindings", [])
        if not bindings:
            return None
        uri = bindings[0]["item"]["value"]
        return uri.rsplit("/", 1)[-1]

    async def _fetch_wikidata_relations(self, entity_id: str) -> List[Dict[str, Any]]:
        """
        Fetch subsidiary (target acquired other) and owned-by/parent-org
        (target was acquired by other) relations for a Wikidata entity,
        including each relation's start-time qualifier (used as the
        acquisition date) and the other entity's official website.

        Args:
            entity_id: Wikidata Q-id of the target's entity

        Returns:
            List of relation dicts with relationship/org_name/domain/date
        """
        query = f"""
        SELECT ?relation ?otherLabel ?website ?start WHERE {{
          {{
            wd:{entity_id} p:P355 ?stmt .
            ?stmt ps:P355 ?other .
            BIND("acquired" AS ?relation)
          }}
          UNION
          {{
            wd:{entity_id} p:P127 ?stmt .
            ?stmt ps:P127 ?other .
            BIND("acquired_by" AS ?relation)
          }}
          UNION
          {{
            wd:{entity_id} p:P749 ?stmt .
            ?stmt ps:P749 ?other .
            BIND("acquired_by" AS ?relation)
          }}
          OPTIONAL {{ ?stmt pq:P580 ?start . }}
          OPTIONAL {{ ?other wdt:P856 ?website . }}
          SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
        }}
        """
        data = await self._run_sparql_query(query)

        relations = []
        for binding in data.get("results", {}).get("bindings", []):
            org_name = binding.get("otherLabel", {}).get("value")
            if not org_name:
                continue

            start = binding.get("start", {}).get("value")
            relations.append(
                {
                    "relationship": binding["relation"]["value"],
                    "org_name": org_name,
                    "domain": _looks_like_domain_website(binding.get("website")),
                    "date": start[:10] if start else None,
                }
            )
        return relations

    async def _run_sparql_query(self, query: str) -> Dict[str, Any]:
        """
        Execute a SPARQL query against Wikidata's public query service.

        Args:
            query: SPARQL query string

        Returns:
            Parsed JSON response
        """
        async with self.session.get(
            _WIKIDATA_SPARQL_ENDPOINT,
            params={"query": query, "format": "json"},
            headers={
                "Accept": "application/sparql-results+json",
                "User-Agent": get_config("user_agent"),
            },
        ) as response:
            if response.status != 200:
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=f"Wikidata SPARQL returned status {response.status}",
                )
            return await response.json()

    def _check_and_run_security_trails(self, domain: str) -> Optional[asyncio.Task]:
        """
        Check if SecurityTrails API is available and run query if it is.

        Args:
            domain: Domain to query

        Returns:
            Task for SecurityTrails API query or None if API not available
        """
        if is_api_configured("securitytrails"):
            return asyncio.create_task(self._query_security_trails(domain))
        return None

    async def _get_news_acquisitions(self, org_name: str) -> None:
        """
        Search recent news coverage for acquisition mentions involving the
        target org. Matches are regex-derived from free text, so they start
        at "low" confidence; a domain is only attached once confirmed via
        WHOIS org-name overlap (see `_confirm_domain_for_org`).

        Args:
            org_name: Organization name to search for (from WHOIS, or a
                domain-derived fallback)
        """
        try:
            from farsight.modules.news import GNEWS_AVAILABLE, NewsMonitor

            if not GNEWS_AVAILABLE:
                logger.info(
                    "gnews not available; skipping news-based acquisition search"
                )
                return

            lookback_days = get_config("acquisition_news_lookback_days", 730)
            patterns = self._build_acquisition_patterns(org_name)
            seen = set()

            async with NewsMonitor() as monitor:
                for query in (f'"{org_name}" acquires', f'"{org_name}" acquired by'):
                    news_result = await monitor.monitor(query, days=lookback_days)

                    for article in news_result.get("articles", []):
                        text = f"{article.get('title', '')} {article.get('snippet', '')}"

                        for pattern, relationship in patterns:
                            match = pattern.search(text)
                            if not match:
                                continue

                            candidate = self._clean_acquisition_name(match.group(1))
                            if not candidate or candidate.lower() == org_name.lower():
                                continue

                            key = (relationship, candidate.lower())
                            if key in seen:
                                continue
                            seen.add(key)

                            domain = await self._confirm_domain_for_org(candidate)

                            self.results["acquisitions"].append(
                                {
                                    "source": "news",
                                    "relationship": relationship,
                                    "org_name": candidate,
                                    "domain": domain,
                                    "date": article.get("published"),
                                    "evidence_url": article.get("url"),
                                    "confidence": "medium" if domain else "low",
                                }
                            )

            if seen:
                logger.info(f"Retrieved {len(seen)} candidate acquisitions from news")
        except Exception as e:
            logger.error(
                f"Error searching news for acquisitions involving {org_name}: {str(e)}"
            )

    @staticmethod
    def _build_acquisition_patterns(org_name: str) -> List[Any]:
        """Build regexes that catch both acquisition directions ("target
        acquires X" and "target acquired by X") for a given org name.

        Only the org name and the acquisition-verb phrase are matched
        case-insensitively (via scoped `(?i:...)` groups); the captured
        fragment itself stays case-sensitive since `[A-Z]`-starts-word is
        the whole signal used to spot a proper noun in free text -- a bare
        `re.IGNORECASE` flag would let lowercase filler words match too.
        """
        escaped = re.escape(org_name)
        return [
            (
                re.compile(
                    rf"(?i:{escaped})\s+(?i:(?:has\s+)?(?:acquires?|acquired|to acquire))\s+"
                    rf"{_ACQUISITION_NAME_FRAGMENT}"
                ),
                "acquired",
            ),
            (
                re.compile(
                    rf"{_ACQUISITION_NAME_FRAGMENT}\s+(?i:acquires|has acquired|to acquire)\s+"
                    rf"(?i:{escaped})"
                ),
                "acquired_by",
            ),
            (
                re.compile(
                    rf"(?i:{escaped})\s+(?i:is|was|has been)\s+(?i:acquired by)\s+"
                    rf"{_ACQUISITION_NAME_FRAGMENT}"
                ),
                "acquired_by",
            ),
        ]

    @staticmethod
    def _clean_acquisition_name(raw: str) -> str:
        """Trim trailing connector words the fragment regex over-captured,
        e.g. "Acme Corp for" -> "Acme Corp"."""
        name = raw.strip().rstrip(".,;:")
        words = name.split()
        while words and words[-1].lower() in _ACQUISITION_TRAILING_STOPWORDS:
            words.pop()
        return " ".join(words)

    async def _confirm_domain_for_org(self, org_name: str) -> Optional[str]:
        """
        Best-effort domain resolution for a news-derived acquisition: guess a
        .com domain from the company name and confirm it via WHOIS org-field
        token overlap. Returns None (rather than a possibly-wrong guess) when
        confirmation fails.

        Args:
            org_name: Candidate acquired/acquiring company name

        Returns:
            Confirmed domain, or None if it couldn't be confirmed
        """
        guess = re.sub(r"[^a-z0-9]", "", org_name.lower())
        if not guess:
            return None
        guessed_domain = f"{guess}.com"

        try:
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, guessed_domain)
        except Exception:
            return None

        whois_org = getattr(whois_data, "org", None)
        if not whois_org:
            return None

        significant_org_tokens = {
            token
            for token in re.findall(r"[a-z0-9]+", org_name.lower())
            if len(token) > 2
        }
        whois_tokens = set(re.findall(r"[a-z0-9]+", str(whois_org).lower()))

        if significant_org_tokens and significant_org_tokens & whois_tokens:
            return guessed_domain
        return None

    def _check_and_run_censys(self, domain: str) -> Optional[asyncio.Task]:
        """
        Check if Censys API is available and run query if it is.

        Note: Censys's certificate search (what _query_censys needs) is only
        available on paid/organization API tiers -- free personal-access-token
        accounts get a 403 telling you to use the Platform UI instead. There's
        no header or endpoint fix for that, so this is skipped rather than
        retried and failed on every scan.

        Args:
            domain: Domain to query

        Returns:
            Task for Censys API query or None if API not available
        """
        if is_api_configured("censys"):
            logger.info(
                "Censys certificate search requires a paid/organization API "
                "tier and is not available on free accounts; skipping."
            )
        return None

    async def _query_security_trails(self, domain: str) -> None:
        """
        Query SecurityTrails API for associated domains.

        Args:
            domain: Domain to query
        """
        try:
            # Get Security Trails API handler
            handler = self.api_manager.get_handler("securitytrails")

            # Extract organization from base domain WHOIS if available
            org = None
            if "whois" in self.results and "org" in self.results["whois"]:
                org = self.results["whois"]["org"]

            # If no org found, try with domain query
            if not org:
                # First try to get associated domains using domain as query
                response = await handler.get(f"v1/domain/{domain}/subdomains")
                if response and "subdomains" in response:
                    subdomains = [f"{sub}.{domain}" for sub in response["subdomains"]]

                    # Add to results
                    self.results["api_results"].append(
                        {
                            "source": "securitytrails",
                            "query_type": "subdomains",
                            "domains": subdomains,
                        }
                    )

                    logger.info(
                        f"Retrieved {len(subdomains)} subdomains from SecurityTrails"
                    )
                    return

            # If we have an organization name, search by organization
            if org:
                # Clean up org name and make API-friendly
                org_query = org.strip().replace(",", "").replace(".", "")

                # Search by organization
                response = await handler.get(
                    "v1/domain/search", params={"query": f"organization:{org_query}"}
                )

                if response and "records" in response:
                    domains = [record["hostname"] for record in response["records"]]

                    # Add to results
                    self.results["api_results"].append(
                        {
                            "source": "securitytrails",
                            "query_type": "organization",
                            "organization": org,
                            "domains": domains,
                        }
                    )

                    logger.info(
                        f"Retrieved {len(domains)} domains from SecurityTrails by organization"
                    )
        except Exception as e:
            logger.error(f"Error querying SecurityTrails API: {str(e)}")

    async def _query_censys(self, domain: str) -> None:
        """
        Query Censys API for associated certificates and domains.

        Args:
            domain: Domain to query
        """
        try:
            # Get Censys API handler
            handler = self.api_manager.get_handler("censys")

            # Search certificates
            response = await handler.get(
                "v2/certificates/search",
                params={"q": f"names: {domain}", "per_page": 100},
            )

            if response and "result" in response and "hits" in response["result"]:
                domains = set()

                # Extract domains from certificates
                for cert in response["result"]["hits"]:
                    if "names" in cert:
                        for name in cert["names"]:
                            # Remove wildcards
                            clean_name = re.sub(r"^\*\.", "", name.strip())
                            # Only include if related to target domain
                            if clean_name.endswith(domain) and "." in clean_name:
                                domains.add(clean_name)

                # Add to results if we found any
                if domains:
                    self.results["api_results"].append(
                        {
                            "source": "censys",
                            "query_type": "certificates",
                            "domains": list(domains),
                        }
                    )

                    logger.info(f"Retrieved {len(domains)} domains from Censys")
        except Exception as e:
            logger.error(f"Error querying Censys API: {str(e)}")

    def _check_and_run_crunchbase(
        self, domain: str, org_name: str
    ) -> Optional[asyncio.Task]:
        """
        Check if the Crunchbase API is available and run query if it is.

        Crunchbase's REST API has had no usable free tier since ~2020
        (Enterprise/paid only), so this is opt-in like SecurityTrails: it
        only fires for users who've configured a key.

        Args:
            domain: Domain to query
            org_name: Organization name to search for

        Returns:
            Task for Crunchbase API query or None if API not available
        """
        if is_api_configured("crunchbase"):
            return asyncio.create_task(self._query_crunchbase(domain, org_name))
        return None

    async def _query_crunchbase(self, domain: str, org_name: str) -> None:
        """
        Query Crunchbase for acquisitions the target organization made
        (acquiree_acquisitions) or was subject to (acquirer_acquisitions).

        Field/card names below match Crunchbase's v4 REST API docs at time
        of writing. Response parsing is defensive (nested `.get()` chains,
        try/except per record) since this can't be verified against a live
        key here -- a shape mismatch degrades to "no Crunchbase results"
        rather than failing the scan.

        Args:
            domain: Domain to query
            org_name: Organization name to search for
        """
        try:
            handler = self.api_manager.get_handler("crunchbase")

            permalink = await self._resolve_crunchbase_permalink(
                handler, domain, org_name
            )
            if not permalink:
                return

            response = await handler.get(
                f"entities/organizations/{permalink}",
                params={"card_ids": "acquiree_acquisitions,acquirer_acquisitions"},
            )
            if not response:
                return

            cards = response.get("cards", {}) or {}
            found = 0

            for record in cards.get("acquiree_acquisitions") or []:
                if self._append_crunchbase_acquisition(record, "acquired"):
                    found += 1

            for record in cards.get("acquirer_acquisitions") or []:
                if self._append_crunchbase_acquisition(record, "acquired_by"):
                    found += 1

            if found:
                logger.info(f"Retrieved {found} acquisitions from Crunchbase")
        except Exception as e:
            logger.error(f"Error querying Crunchbase API: {str(e)}")

    async def _resolve_crunchbase_permalink(
        self, handler: Any, domain: str, org_name: str
    ) -> Optional[str]:
        """
        Resolve the target to a Crunchbase organization permalink: try a
        domain-field search first (most precise), then fall back to an
        organization-name autocomplete lookup.

        Args:
            handler: Crunchbase APIHandler
            domain: Domain to search for
            org_name: Organization name to search for as a fallback

        Returns:
            Crunchbase permalink, or None if no match was found
        """
        try:
            search_response = await handler.post(
                "searches/organizations",
                data={
                    "field_ids": ["identifier"],
                    "query": [
                        {
                            "type": "predicate",
                            "field_id": "website",
                            "operator_id": "contains",
                            "values": [domain],
                        }
                    ],
                    "limit": 1,
                },
            )
            for entity in (search_response or {}).get("entities", []):
                permalink = (entity.get("identifier") or {}).get("permalink")
                if permalink:
                    return permalink
        except Exception as e:
            logger.warning(f"Crunchbase domain search failed for {domain}: {str(e)}")

        try:
            response = await handler.get(
                "autocompletes",
                params={
                    "query": org_name,
                    "collection_ids": "organizations",
                    "limit": 5,
                },
            )
            for entity in (response or {}).get("entities", []):
                permalink = (entity.get("identifier") or {}).get("permalink")
                if permalink:
                    return permalink
        except Exception as e:
            logger.warning(
                f"Crunchbase autocomplete lookup failed for {org_name}: {str(e)}"
            )

        return None

    def _append_crunchbase_acquisition(
        self, record: Dict[str, Any], relationship: str
    ) -> bool:
        """
        Parse one Crunchbase acquisition card record and append it to
        results if it names the other party. Malformed records are skipped
        rather than raised, since the exact card shape isn't verified here.

        Args:
            record: A single acquiree_acquisitions/acquirer_acquisitions entry
            relationship: "acquired" or "acquired_by"

        Returns:
            True if a record was appended, False if it was skipped
        """
        try:
            properties = record.get("properties", {}) or {}
            other_key = "acquiree" if relationship == "acquired" else "acquirer"
            other_side = properties.get(other_key) or {}

            org_name = other_side.get("value")
            if not org_name:
                return False

            domain = _looks_like_domain_website(
                properties.get(f"{other_key}_website")
                or properties.get("website")
                or properties.get("domain")
            )

            permalink = other_side.get("permalink")
            evidence_url = (
                f"https://www.crunchbase.com/organization/{permalink}"
                if permalink
                else None
            )

            self.results["acquisitions"].append(
                {
                    "source": "crunchbase",
                    "relationship": relationship,
                    "org_name": org_name,
                    "domain": domain,
                    "date": properties.get("announced_on"),
                    "evidence_url": evidence_url,
                    "confidence": "high" if domain else "medium",
                }
            )
            return True
        except Exception as e:
            logger.warning(f"Skipping malformed Crunchbase acquisition record: {str(e)}")
            return False
