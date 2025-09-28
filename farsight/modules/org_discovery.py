"""Organization domain discovery module for FARSIGHT.

This module discovers domains related to an organization through various
techniques including WHOIS analysis, certificate transparency logs, and
passive DNS data collection.
"""

import asyncio
import whois
import aiohttp
import re
from typing import Dict, List, Set, Optional, Any
from bs4 import BeautifulSoup
import json
import urllib.parse

from farsight.utils.common import logger, retry
from farsight.utils.api_handler import APIManager
from farsight.config import get_config, is_api_configured


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
        }
        
        # Use appropriate methods based on depth
        tasks = [self._get_whois_info(domain)]
        
        # Always check certificate transparency
        tasks.append(self._get_crt_sh_domains(domain))
        
        # Deeper scans
        if depth >= 2:
            # Add passive DNS lookup
            tasks.append(self._get_passive_dns(domain))
            
            # Try API-based methods if available
            security_trails_task = self._check_and_run_security_trails(domain)
            if security_trails_task:
                tasks.append(security_trails_task)
        
        # For maximum depth, try additional API sources
        if depth >= 3:
            censys_task = self._check_and_run_censys(domain)
            if censys_task:
                tasks.append(censys_task)
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)
        
        # Process and deduplicate results
        base_domain_parts = domain.split('.')
        base_domain_suffix = '.'.join(base_domain_parts[-2:])  # e.g., 'sony.com'
        
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
            if discovered.endswith('.' + domain):  # It's a subdomain
                subdomains.add(discovered)
            elif '.' + base_domain_suffix in discovered:  # It's a subdomain of the main domain
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
            "total_subdomains": len(sorted_subdomains)
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
            self.results["whois"] = {k: v for k, v in self.results["whois"].items() if v is not None}
            
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
        
        crt_sh_url = f"https://crt.sh/?q=%.{domain}&output=json"
        domains = set()
        
        try:
            async with self.session.get(crt_sh_url) as response:
                if response.status == 200:
                    # Parse JSON response
                    data = await response.json()
                    
                    # Extract domains from common_name and name_value fields
                    for cert in data:
                        if "common_name" in cert and cert["common_name"]:
                            domains.add(cert["common_name"])
                        
                        if "name_value" in cert and cert["name_value"]:
                            # Split name_value on newlines and extract domains
                            for name in cert["name_value"].split("\\n"):
                                # Remove wildcards
                                clean_name = re.sub(r"^\*\.", "", name.strip())
                                if clean_name.endswith(domain) and "." in clean_name:
                                    domains.add(clean_name)
                    
                    logger.info(f"Retrieved {len(domains)} domains from crt.sh")
                    self.results["crt_sh"] = list(domains)
                else:
                    logger.warning(f"crt.sh returned status {response.status}")
        except Exception as e:
            logger.error(f"Error querying crt.sh: {str(e)}")
    
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
                rapid_dns_url, 
                headers={"User-Agent": get_config("user_agent")}
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
                dnsdb_url,
                headers={"User-Agent": get_config("user_agent")}
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
                    
                    logger.info(f"Retrieved additional domains from DNSDB.io")
        except Exception as e:
            logger.error(f"Error querying DNSDB.io: {str(e)}")
        
        self.results["passive_dns"] = list(domains)
    
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
    
    def _check_and_run_censys(self, domain: str) -> Optional[asyncio.Task]:
        """
        Check if Censys API is available and run query if it is.
        
        Args:
            domain: Domain to query
            
        Returns:
            Task for Censys API query or None if API not available
        """
        if is_api_configured("censys"):
            return asyncio.create_task(self._query_censys(domain))
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
                    self.results["api_results"].append({
                        "source": "securitytrails",
                        "query_type": "subdomains",
                        "domains": subdomains,
                    })
                    
                    logger.info(f"Retrieved {len(subdomains)} subdomains from SecurityTrails")
                    return
            
            # If we have an organization name, search by organization
            if org:
                # Clean up org name and make API-friendly
                org_query = org.strip().replace(",", "").replace(".", "")
                
                # Search by organization
                response = await handler.get(
                    "v1/domain/search",
                    params={"query": f"organization:{org_query}"}
                )
                
                if response and "records" in response:
                    domains = [record["hostname"] for record in response["records"]]
                    
                    # Add to results
                    self.results["api_results"].append({
                        "source": "securitytrails",
                        "query_type": "organization",
                        "organization": org,
                        "domains": domains,
                    })
                    
                    logger.info(f"Retrieved {len(domains)} domains from SecurityTrails by organization")
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
                params={"q": f"names: {domain}", "per_page": 100}
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
                    self.results["api_results"].append({
                        "source": "censys",
                        "query_type": "certificates",
                        "domains": list(domains),
                    })
                    
                    logger.info(f"Retrieved {len(domains)} domains from Censys")
        except Exception as e:
            logger.error(f"Error querying Censys API: {str(e)}")
