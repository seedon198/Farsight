"""Advanced subdomain enumeration module for FARSIGHT."""

import asyncio
import aiohttp
import aiodns
import json
import re
import time
import random
from typing import Dict, List, Set, Optional, Any, Tuple, Union
import dns.resolver
import ipaddress
import requests

from farsight.utils.common import logger, retry
from farsight.utils.dns import DNSResolver, is_domain_alive
from farsight.config import get_config

# Common subdomain sources
SOURCES = {
    "crt_sh": "https://crt.sh/?q=%.{}&output=json",
    "virustotal": "https://www.virustotal.com/vtapi/v2/domain/report",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={}",
    "threatcrowd": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
    "bufferover": "https://dns.bufferover.run/dns?q=.{}",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
    "urlscan": "https://urlscan.io/api/v1/search/?q=domain:{}",
}

# Subdomain common patterns
COMMON_SUBDOMAIN_PATTERNS = [
    r'//([a-zA-Z0-9][a-zA-Z0-9-]*)\.' + r'{}',  # Common HTTP pattern
    r'https?://([a-zA-Z0-9][a-zA-Z0-9-]*?)\.' + r'{}[\/"\':\s]',  # URLs
    r'href=["\']https?://([a-zA-Z0-9][a-zA-Z0-9-]*?)\.' + r'{}[/"\'>\s]',  # HREF values
    r'src=["\']https?://([a-zA-Z0-9][a-zA-Z0-9-]*?)\.' + r'{}[/"\'>\s]',  # SRC attributes
    r'["\']https?://([a-zA-Z0-9][a-zA-Z0-9-]*?)\.' + r'{}[/"\'>\s]',  # String literals
    r'https?:\\\\([a-zA-Z0-9][a-zA-Z0-9-]*?)\.' + r'{}[\\"\'\s]',  # Escaped URLs
    r'data-domain=["\']([a-zA-Z0-9][a-zA-Z0-9-]*?)\.' + r'{}["\']',  # Custom data attributes
]

class SubdomainEnumerator:
    """Advanced Subdomain Enumeration Class."""
    
    def __init__(self):
        """Initialize the subdomain enumerator."""
        self.dns_resolver = DNSResolver()
        self.session = None
        self.discovered = set()
        self.sources_results = {}
        
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
    
    async def enumerate(self, domain: str, techniques: Optional[List[str]] = None, max_results: int = 500) -> List[str]:
        """
        Enumerate subdomains using multiple techniques.
        
        Args:
            domain: Base domain to find subdomains for
            techniques: List of techniques to use (default: all)
            max_results: Maximum number of verified subdomains to return
            
        Returns:
            List of discovered subdomains
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async with context.")
            
        self.discovered = set()
        self.sources_results = {}
        
        if not techniques:
            techniques = ["brute", "crt", "scrape", "permutation", "apis"]
        
        # Start with certificate transparency logs as it's usually the most reliable
        if "crt" in techniques:
            await self._query_crt_sh(domain)
            logger.info(f"Found {len(self.discovered)} domains via certificate transparency logs")
            
            # Early return if we found enough subdomains from crt.sh
            if len(self.discovered) > max_results * 2:
                logger.info(f"Found more than {max_results*2} subdomains from certificate logs, skipping other methods")
                techniques = []
        
        tasks = []
        
        # DNS brute force with large wordlist
        if "brute" in techniques:
            tasks.append(self._brute_force(domain))
        
        # Permutation-based discovery
        if "permutation" in techniques:
            tasks.append(self._permutation_scan(domain))
        
        # Web scraping and search engine discovery
        if "scrape" in techniques:
            tasks.append(self._scrape_search_engines(domain))
        
        # Public APIs
        if "apis" in techniques:
            # Add API-based discovery methods
            tasks.append(self._query_hackertarget(domain))
            tasks.append(self._query_threatcrowd(domain))
            tasks.append(self._query_bufferover(domain))
            tasks.append(self._query_alienvault(domain))
            tasks.append(self._query_urlscan(domain))
            
            # Only query VirusTotal if API key is available
            virustotal_api_key = get_config("FARSIGHT_VIRUSTOTAL_API_KEY", None)
            if virustotal_api_key:
                tasks.append(self._query_virustotal(domain, virustotal_api_key))
        
        # Run remaining techniques concurrently if needed
        if tasks:
            await asyncio.gather(*tasks)
        
        # Convert discovered set to list and filter valid domains
        logger.info(f"Total discovered subdomains before validation: {len(self.discovered)}")
        
        # Filter out domain names that exceed DNS limits
        all_discovered = []
        for subdomain in self.discovered:
            # Domain names have a max length of 253 characters
            if len(subdomain) <= 253 and subdomain.count('.') <= 127:
                all_discovered.append(subdomain)
        
        logger.info(f"Subdomains within DNS limits: {len(all_discovered)}")
        
        # Verify discovered subdomains in batches (to avoid overwhelming DNS)
        valid_domains = []
        batch_size = 50
        
        for i in range(0, min(len(all_discovered), max_results * 2), batch_size):
            if len(valid_domains) >= max_results:
                break
                
            batch = all_discovered[i:i+batch_size]
            try:
                dns_results = await self.dns_resolver.bulk_resolve(batch, ['A'])
                
                for subdomain, records in dns_results.items():
                    if 'A' in records and records['A']:
                        valid_domains.append(subdomain)
                        
                        # Exit early if we have enough results
                        if len(valid_domains) >= max_results:
                            break
            except Exception as e:
                logger.error(f"Error resolving batch: {str(e)}")
        
        logger.info(f"Final verified subdomains: {len(valid_domains)}")
        return sorted(valid_domains[:max_results])
    
    async def _query_crt_sh(self, domain: str) -> None:
        """
        Query certificate transparency logs via crt.sh.
        
        Args:
            domain: Base domain to search for
        """
        try:
            url = SOURCES["crt_sh"].format(domain)
            async with self.session.get(url) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        
                        # Process certificate data
                        for cert in data:
                            if "name_value" in cert:
                                # Split multi-domain certificates
                                names = cert["name_value"].split("\\n")
                                for name in names:
                                    if domain in name.lower():
                                        if name.startswith("*."):
                                            name = name[2:]  # Remove *. prefix
                                        self.discovered.add(name.lower())
                        
                        self.sources_results["crt_sh"] = len(self.discovered)
                        logger.info(f"Found {len(self.discovered)} subdomains via crt.sh")
                    except Exception as e:
                        logger.error(f"Error parsing crt.sh response: {str(e)}")
                else:
                    logger.warning(f"crt.sh returned status {response.status}")
        except Exception as e:
            logger.error(f"Error querying crt.sh: {str(e)}")
            
    async def _brute_force(self, domain: str) -> None:
        """
        Perform DNS brute force using a large wordlist.
        
        Args:
            domain: Base domain to brute force
        """
        try:
            # Load extensive wordlist for more thorough discovery
            # Use a combination of common subdomain names + common subdomain patterns
            wordlist = await self._load_wordlist()
            
            # Generate subdomains to test
            subdomains_to_check = [f"{word}.{domain}" for word in wordlist]
            
            # Check in batches to avoid overwhelming DNS servers
            batch_size = 100
            total_checked = 0
            
            for i in range(0, len(subdomains_to_check), batch_size):
                batch = subdomains_to_check[i:i+batch_size]
                dns_results = await self.dns_resolver.bulk_resolve(batch, ['A'])
                
                for subdomain, records in dns_results.items():
                    if 'A' in records and records['A']:
                        self.discovered.add(subdomain.lower())
                
                total_checked += len(batch)
                logger.debug(f"Brute force progress: {total_checked}/{len(subdomains_to_check)}")
                # Small delay to be respectful to DNS servers
                await asyncio.sleep(0.5)
            
            self.sources_results["brute_force"] = len(self.discovered)
            logger.info(f"Found {len(self.discovered)} subdomains via brute force")
        except Exception as e:
            logger.error(f"Error during brute force: {str(e)}")
    
    async def _load_wordlist(self) -> List[str]:
        """
        Load an extensive subdomain wordlist.
        
        Returns:
            List of subdomain prefixes
        """
        # Start with a comprehensive default list
        wordlist = [
            # Common subdomains (first letter variations for better coverage)
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
            "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
            
            # Common functional names
            "www", "mail", "email", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "ns3", "ns4", "smtp", "secure", "vpn", "m", "shop", "ftp", "calendar",
            "admin", "dev", "developer", "developers", "development", "staging", 
            "test", "testing", "tst", "qa", "prod", "production", "app", "apps",
            "api", "apis", "auth", "beta", "cdn", "cloud", "cms", "connect", "console",
            "demo", "direct", "docs", "documentation", "exchange", "files", "ftp", "git",
            "help", "host", "images", "img", "internal", "int", "intranet", "portal", 
            "login", "mobile", "new", "news", "old", "portal", "s3", "shop", "sites",
            "sso", "staff", "store", "support", "web", "ww", "wwww", "www2", "www3",
            "media", "assets", "download", "downloads", "careers", "jobs", "investor",
            "status", "static", "chat", "forum", "community", "db", "database", "repo",
            "de", "fr", "uk", "us", "eu", "es", "jp", "au", "ca", "ru", "it",
            
            # Corporate focused
            "corporate", "corp", "investor", "investors", "ir", "finance", "hr", "jira",
            "confluence", "wiki", "partners", "partner", "team", "teams", "sales", "marketing",
            "design", "it", "uat", "stg", "training", "edu", "research", "labs",
            
            # Service-oriented
            "accounts", "account", "analytics", "aws", "azure", "gcp", "gcs", "jenkins",
            "kubernetes", "k8s", "docker", "gitlab", "github", "grafana", "kibana", "monitor",
            "prometheus", "slack", "jira", "confluence", "vpn", "proxy", "ldap", "active-directory",
            "ad", "email", "smtp", "pop", "pop3", "imap", "webmail", "caldav", "calendar",
            "conference", "meet", "zoom", "drive", "docs", "sheets", "slides", "office",
            
            # Gaming (for Sony specifically)
            "ps", "ps1", "ps2", "ps3", "ps4", "ps5", "playstation", "psn", "store",
            "games", "gaming", "game", "players"
        ]
        
        # Add common number patterns
        wordlist.extend([f"dev{i}" for i in range(1, 6)])
        wordlist.extend([f"test{i}" for i in range(1, 6)])
        wordlist.extend([f"demo{i}" for i in range(1, 6)])
        wordlist.extend([f"staging{i}" for i in range(1, 6)])
        wordlist.extend([f"prod{i}" for i in range(1, 6)])
        wordlist.extend([f"uat{i}" for i in range(1, 6)])
        
        return wordlist
    
    async def _permutation_scan(self, domain: str) -> None:
        """
        Perform permutation-based subdomain scanning.
        
        Args:
            domain: Base domain to generate permutations for
        """
        try:
            # Get discovered domains so far to generate permutations
            base_domains = list(self.discovered)
            if not base_domains:
                # If no domains discovered yet, add common ones
                base_domains = [f"www.{domain}", f"mail.{domain}", f"support.{domain}"]
            
            # Generate permutations
            permutations = set()
            for base in base_domains:
                # Extract the subdomain part
                if base.endswith(domain):
                    parts = base.replace("." + domain, "").split(".")
                    for part in parts:
                        if len(part) >= 2:  # Only use meaningful parts
                            permutations.add(f"{part}-dev.{domain}")
                            permutations.add(f"{part}-test.{domain}")
                            permutations.add(f"{part}-staging.{domain}")
                            permutations.add(f"{part}-prod.{domain}")
                            permutations.add(f"dev-{part}.{domain}")
                            permutations.add(f"test-{part}.{domain}")
                            permutations.add(f"staging-{part}.{domain}")
                            permutations.add(f"prod-{part}.{domain}")
                            permutations.add(f"{part}2.{domain}")
                            permutations.add(f"{part}3.{domain}")
                            # For each part, try common additions
                            for addition in ["api", "app", "portal", "admin", "internal"]:
                                permutations.add(f"{part}-{addition}.{domain}")
                                permutations.add(f"{addition}-{part}.{domain}")
            
            # Check permutations in batches
            batch_size = 50
            permutation_list = list(permutations)
            valid_count = 0
            
            for i in range(0, len(permutation_list), batch_size):
                batch = permutation_list[i:i+batch_size]
                dns_results = await self.dns_resolver.bulk_resolve(batch, ['A'])
                
                for subdomain, records in dns_results.items():
                    if 'A' in records and records['A']:
                        self.discovered.add(subdomain.lower())
                        valid_count += 1
                
                # Small delay to be respectful to DNS servers
                await asyncio.sleep(0.5)
            
            logger.info(f"Found {valid_count} subdomains via permutation scanning")
            self.sources_results["permutation"] = valid_count
            
        except Exception as e:
            logger.error(f"Error during permutation scanning: {str(e)}")
    
    async def _scrape_search_engines(self, domain: str) -> None:
        """
        Scrape search engines for subdomain mentions.
        
        Args:
            domain: Base domain to search for
        """
        try:
            # This would normally involve scraping search engines,
            # but for ethical and ToS reasons, we'll use a simpler approach
            
            # Simulate scraping by checking common patterns on the main website
            async with self.session.get(f"https://{domain}", ssl=False) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # Look for subdomain patterns in the response
                    for pattern in COMMON_SUBDOMAIN_PATTERNS:
                        compiled_pattern = re.compile(pattern.format(re.escape(domain)))
                        matches = compiled_pattern.findall(text)
                        
                        for match in matches:
                            if match and len(match) > 1:  # Filter out empty matches
                                self.discovered.add(f"{match}.{domain}".lower())
            
            self.sources_results["scrape"] = len(self.discovered)
            logger.info(f"Found {len(self.discovered)} subdomains via scraping")
            
        except Exception as e:
            logger.error(f"Error during web scraping: {str(e)}")
    
    async def _query_hackertarget(self, domain: str) -> None:
        """Query HackerTarget API for subdomains."""
        try:
            url = SOURCES["hackertarget"].format(domain)
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    if "API count exceeded" not in text:
                        lines = text.split('\n')
                        for line in lines:
                            if line.strip():
                                parts = line.split(',')
                                if len(parts) >= 1:
                                    subdomain = parts[0].strip().lower()
                                    if domain in subdomain:
                                        self.discovered.add(subdomain)
            
            logger.info(f"Found {len(self.discovered)} subdomains via HackerTarget")
        except Exception as e:
            logger.error(f"Error querying HackerTarget API: {str(e)}")
    
    async def _query_threatcrowd(self, domain: str) -> None:
        """Query ThreatCrowd API for subdomains."""
        try:
            url = SOURCES["threatcrowd"].format(domain)
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("response_code") == "1":
                        subdomains = data.get("subdomains", [])
                        for subdomain in subdomains:
                            self.discovered.add(subdomain.lower())
            
            logger.info(f"Found {len(self.discovered)} subdomains via ThreatCrowd")
        except Exception as e:
            logger.error(f"Error querying ThreatCrowd API: {str(e)}")
    
    async def _query_bufferover(self, domain: str) -> None:
        """Query BufferOver API for subdomains."""
        try:
            url = SOURCES["bufferover"].format(domain)
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "FDNS_A" in data and data["FDNS_A"]:
                        records = data["FDNS_A"].split(',')
                        for record in records:
                            try:
                                ip, host = record.split(',')
                                if domain in host:
                                    self.discovered.add(host.lower())
                            except:
                                continue
            
            logger.info(f"Found {len(self.discovered)} subdomains via BufferOver")
        except Exception as e:
            logger.error(f"Error querying BufferOver API: {str(e)}")
    
    async def _query_alienvault(self, domain: str) -> None:
        """Query AlienVault OTX API for subdomains."""
        try:
            url = SOURCES["alienvault"].format(domain)
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "passive_dns" in data:
                        for record in data["passive_dns"]:
                            host = record.get("hostname", "")
                            if domain in host:
                                self.discovered.add(host.lower())
            
            logger.info(f"Found {len(self.discovered)} subdomains via AlienVault OTX")
        except Exception as e:
            logger.error(f"Error querying AlienVault OTX API: {str(e)}")
    
    async def _query_urlscan(self, domain: str) -> None:
        """Query URLScan.io API for subdomains."""
        try:
            url = SOURCES["urlscan"].format(domain)
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "results" in data:
                        for result in data["results"]:
                            page = result.get("page", {})
                            host = page.get("domain", "")
                            if domain in host:
                                self.discovered.add(host.lower())
            
            logger.info(f"Found {len(self.discovered)} subdomains via URLScan.io")
        except Exception as e:
            logger.error(f"Error querying URLScan.io API: {str(e)}")
    
    async def _query_virustotal(self, domain: str, api_key: str) -> None:
        """
        Query VirusTotal API for subdomains.
        
        Args:
            domain: Base domain to search for
            api_key: VirusTotal API key
        """
        try:
            url = SOURCES["virustotal"]
            params = {
                "apikey": api_key,
                "domain": domain
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data and "subdomains" in data:
                        for subdomain in data["subdomains"]:
                            self.discovered.add(subdomain.lower())
                elif response.status == 403:
                    logger.warning("VirusTotal API key is invalid or rate limited")
            
            logger.info(f"Found {len(self.discovered)} subdomains via VirusTotal")
        except Exception as e:
            logger.error(f"Error querying VirusTotal API: {str(e)}")

async def discover_subdomains(domain: str, techniques: Optional[List[str]] = None, max_results: int = 500) -> List[str]:
    """
    Wrapper function to discover subdomains using all available techniques.
    
    Args:
        domain: Base domain to find subdomains for
        techniques: List of techniques to use (default: all)
        max_results: Maximum number of verified subdomains to return
        
    Returns:
        List of discovered subdomains
    """
    async with SubdomainEnumerator() as enumerator:
        return await enumerator.enumerate(domain, techniques, max_results)
