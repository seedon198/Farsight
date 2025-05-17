"""Reconnaissance and asset discovery module for FARSIGHT."""

import asyncio
import ipaddress
from typing import Dict, List, Set, Optional, Any, Tuple, Union
import socket
import time
import os
import json
import csv
from pathlib import Path

from farsight.utils.common import logger, retry
from farsight.utils.api_handler import APIManager
from farsight.utils.dns import DNSResolver, PortScanner, enum_subdomains, check_spf_dmarc
from farsight.utils.subdomain_enum import discover_subdomains
from farsight.config import get_config, is_api_configured, REPORTS_DIR


class Recon:
    """Reconnaissance and asset discovery class."""
    
    def __init__(self, api_manager: Optional[APIManager] = None):
        """
        Initialize recon module.
        
        Args:
            api_manager: API manager for making API requests (optional)
        """
        self.api_manager = api_manager or APIManager()
        self.dns_resolver = DNSResolver()
        self.port_scanner = PortScanner()
        self.results = {
            "dns": {},
            "subdomains": [],
            "email_security": {},
            "port_scan": {},
            "api_results": [],
        }
    
    async def scan(self, domain: str, depth: int = 1) -> Dict[str, Any]:
        """
        Perform reconnaissance and asset discovery.
        
        Args:
            domain: Target domain
            depth: Scan depth level (1-3)
            
        Returns:
            Dictionary with scan results
        """
        # Reset results
        self.results = {
            "dns": {},
            "subdomains": [],
            "email_security": {},
            "port_scan": {},
            "api_results": [],
        }
        
        # Basic DNS enumeration
        dns_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        self.results["dns"] = await self.dns_resolver.bulk_resolve([domain], dns_types)
        
        # Get email security status (SPF, DMARC)
        self.results["email_security"] = await check_spf_dmarc(domain)
        
        # Discover subdomains based on depth
        if depth >= 1:
            discovered = await self._discover_subdomains(domain, depth)
            self.results["subdomains"] = discovered
            
            # Get IPs from A records
            ips = await self._get_ips_from_domains([domain] + discovered)
            
            # Port scan the main domain for basic services
            if ips and domain in ips:
                target_ip = ips[domain][0]  # Use first IP if multiple found
                self.results["port_scan"] = await self.port_scanner.scan_ports(target_ip)
        
        # For deeper scan, check API sources and expanded port range
        if depth >= 2:
            # Try API sources for additional information
            shodan_task = self._check_and_run_shodan(domain)
            if shodan_task:
                shodan_result = await shodan_task
                if shodan_result:
                    self.results["api_results"].append(shodan_result)
            
            # Enhanced port scan on main domain with more ports
            if "port_scan" in self.results and self.results["port_scan"]:
                target_ip = self.results["port_scan"]["target"]
                # Expanded port list
                expanded_ports = [
                    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 443, 
                    445, 465, 587, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 
                    5432, 5900, 5901, 6379, 8080, 8443, 8888, 9090, 9200, 27017
                ]
                self.results["port_scan"] = await self.port_scanner.scan_ports(target_ip, expanded_ports)
        
        # For the most comprehensive scan
        if depth >= 3:
            # Try Censys API if available
            censys_task = self._check_and_run_censys(domain)
            if censys_task:
                censys_result = await censys_task
                if censys_result:
                    self.results["api_results"].append(censys_result)
        
        # Process and return results
        return {
            "target_domain": domain,
            "dns_records": self.results["dns"],
            "subdomains": self.results["subdomains"],
            "email_security": self.results["email_security"],
            "port_scan": self.results["port_scan"],
            "api_results": self.results["api_results"],
            "total_subdomains": len(self.results["subdomains"]),
            "timestamp": time.time(),
        }
    
    async def _discover_subdomains(self, domain: str, depth: int) -> List[str]:
        """
        Discover subdomains using various techniques based on scan depth.
        
        Args:
            domain: Target domain
            depth: Scan depth level (1-3)
            
        Returns:
            List of discovered subdomains
        """
        discovered = set()
        
        if depth == 1:
            # Basic discovery with common subdomain prefixes for quick scans
            wordlist = self._get_wordlist(depth)
            basic_discovered = await enum_subdomains(domain, wordlist)
            discovered.update(basic_discovered)
        else:
            # Use advanced subdomain enumeration for more comprehensive discovery
            logger.info(f"Starting advanced subdomain enumeration for {domain}")
            
            # Select techniques based on depth
            techniques = ["crt", "brute"]
            
            if depth >= 2:
                techniques.append("scrape")
                techniques.append("apis")
                
            if depth >= 3:
                techniques.append("permutation")
                
            # Run the advanced subdomain discovery
            advanced_discovered = await discover_subdomains(domain, techniques)
            logger.info(f"Advanced subdomain enumeration found {len(advanced_discovered)} subdomains")
            discovered.update(advanced_discovered)
        
            # Try to find nameservers and attempt zone transfer
            ns_records = await self.dns_resolver.resolve(domain, 'NS')
            for record in ns_records:
                if 'nameserver' in record:
                    ns = record['nameserver']
                    zone_transfer_results = await self._try_zone_transfer(domain, ns)
                    if zone_transfer_results:
                        discovered.update(zone_transfer_results)
        
        
        # Return sorted list
        return sorted(list(discovered))
    
    async def _get_ips_from_domains(self, domains: List[str]) -> Dict[str, List[str]]:
        """
        Get IP addresses for a list of domains.
        
        Args:
            domains: List of domains
            
        Returns:
            Dictionary mapping domains to their IP addresses
        """
        ip_mapping = {}
        dns_results = await self.dns_resolver.bulk_resolve(domains, ['A'])
        
        for domain, records in dns_results.items():
            if 'A' in records and records['A']:
                ip_mapping[domain] = [record['ip'] for record in records['A']]
        
        return ip_mapping
    
    def _get_wordlist(self, depth: int) -> List[str]:
        """
        Get subdomain wordlist based on scan depth.
        
        Args:
            depth: Scan depth level (1-3)
            
        Returns:
            Wordlist of subdomain prefixes
        """
        # In a real implementation, this would load from files
        # For now, use hardcoded lists of increasing size
        if depth == 1:
            # Small list (basic scan)
            return [
                "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
                "smtp", "secure", "vpn", "admin", "dev", "staging", "test"
            ]
        elif depth == 2:
            # Medium list
            return [
                "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
                "smtp", "secure", "vpn", "admin", "dev", "staging", "test", "portal",
                "api", "apps", "auth", "beta", "cdn", "cloud", "cms", "connect",
                "demo", "direct", "docs", "exchange", "files", "help", "host",
                "intranet", "login", "mobile", "new", "news", "old", "owa", "shop",
                "sites", "sso", "staff", "store", "support", "web"
            ]
        else:
            # Large list (comprehensive scan)
            # In a real implementation, this would be a much larger list from a file
            return [
                "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
                "smtp", "secure", "vpn", "admin", "dev", "staging", "test", "portal",
                "api", "apps", "auth", "beta", "cdn", "cloud", "cms", "connect",
                "demo", "direct", "docs", "exchange", "files", "help", "host",
                "intranet", "login", "mobile", "new", "news", "old", "owa", "shop", 
                "sites", "sso", "staff", "store", "support", "web", "ftp", "sftp",
                "backup", "db", "database", "data", "sql", "mysql", "oracle", "ssh",
                "git", "svn", "jenkins", "ci", "jira", "confluence", "wiki", "proxy",
                "internal", "external", "extranet", "tms", "crm", "hr", "it", "uat", 
                "qa", "prod", "production", "development", "stage", "corp", "corporate",
                "partners", "partner", "clients", "client", "customers", "customer",
                "sales", "marketing", "finance", "accounting", "billing", "payment",
                "payments", "pay", "order", "orders", "shipping", "status", "track",
                "tracking", "media", "image", "images", "img", "static", "assets",
                "js", "css", "style", "styles", "fonts", "font", "cdn1", "cdn2",
                "download", "downloads", "upload", "uploads", "file", "ws", "m",
                "services", "service", "api1", "api2", "feeds", "feed", "rss", "app",
                "apps", "mobile", "smtp1", "smtp2", "ns3", "ns4", "dns", "dns1", "dns2"
            ]
    
    async def _try_zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        """
        Attempt DNS zone transfer from a nameserver.
        
        Args:
            domain: Target domain
            nameserver: Nameserver to try zone transfer from
            
        Returns:
            List of discovered domains from zone transfer
        """
        # This would be implemented with a proper zone transfer utility
        # For now, return empty list as this is usually not allowed
        logger.info(f"Attempting zone transfer for {domain} from {nameserver}")
        return []
    
    def _check_and_run_shodan(self, domain: str) -> Optional[asyncio.Task]:
        """
        Check if Shodan API is available and run query if it is.
        
        Args:
            domain: Domain to query
            
        Returns:
            Task for Shodan API query or None if API not available
        """
        if is_api_configured("shodan"):
            return self._query_shodan(domain)
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
            return self._query_censys(domain)
        return None
    
    async def _query_shodan(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Query Shodan API for information about domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with Shodan API results
        """
        try:
            # Get Shodan API handler
            handler = self.api_manager.get_handler("shodan")
            
            # Query for hosts information
            response = await handler.get("shodan/host/search", params={"query": f"hostname:{domain}"})
            
            if response and "matches" in response:
                hosts = []
                
                for host in response["matches"]:
                    host_info = {
                        "ip": host.get("ip_str"),
                        "ports": host.get("ports", []),
                        "hostnames": host.get("hostnames", []),
                        "os": host.get("os"),
                        "timestamp": host.get("timestamp"),
                    }
                    
                    # Add banner information if available
                    if "data" in host:
                        host_info["banner"] = host["data"][:200]  # Limit size
                    
                    hosts.append(host_info)
                
                return {
                    "source": "shodan",
                    "query": domain,
                    "total_results": response.get("total", 0),
                    "hosts": hosts,
                }
        except Exception as e:
            logger.error(f"Error querying Shodan API: {str(e)}")
        
        return None
    
    async def _query_censys(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Query Censys API for information about domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with Censys API results
        """
        try:
            # Get Censys API handler
            handler = self.api_manager.get_handler("censys")
            
            # Query hosts search
            response = await handler.get(
                "v2/hosts/search",
                params={"q": f"services.tls.certificates.leaf_data.names: {domain}"}
            )
            
            if response and "result" in response and "hits" in response["result"]:
                hosts = []
                
                for hit in response["result"]["hits"]:
                    services = []
                    if "services" in hit:
                        for svc in hit["services"]:
                            service = {
                                "port": svc.get("port"),
                                "service_name": svc.get("service_name"),
                                "transport_protocol": svc.get("transport_protocol"),
                            }
                            services.append(service)
                    
                    host_info = {
                        "ip": hit.get("ip"),
                        "services": services,
                        "location": hit.get("location"),
                        "autonomous_system": hit.get("autonomous_system"),
                    }
                    
                    hosts.append(host_info)
                
                return {
                    "source": "censys",
                    "query": domain,
                    "total_results": response["result"].get("total", 0),
                    "hosts": hosts,
                }
        except Exception as e:
            logger.error(f"Error querying Censys API: {str(e)}")
        
        return None
    
    def export_results(self, results: Dict[str, Any], output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """
        Export scan results to various formats.
        
        Args:
            results: Scan results from the scan method
            output_dir: Directory to save output files
            
        Returns:
            Dictionary mapping export types to output file paths
        """
        if not output_dir:
            # Use reports directory by default
            domain = results.get("target_domain", "unknown")
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_dir = REPORTS_DIR / f"{domain}_{timestamp}"
            output_dir.mkdir(exist_ok=True)
        
        output_files = {}
        
        # Export as JSON
        json_path = output_dir / "recon_results.json"
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
        output_files["json"] = json_path
        
        # Export subdomains as text
        if "subdomains" in results and results["subdomains"]:
            subdomains_path = output_dir / "subdomains.txt"
            with open(subdomains_path, 'w') as f:
                for subdomain in results["subdomains"]:
                    f.write(f"{subdomain}\n")
            output_files["subdomains"] = subdomains_path
        
        # Export port scan results as CSV
        if "port_scan" in results and results["port_scan"] and "ports" in results["port_scan"]:
            ports_path = output_dir / "open_ports.csv"
            with open(ports_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Port", "Banner"])
                for port in results["port_scan"]["ports"]:
                    writer.writerow([
                        results["port_scan"]["target"],
                        port["port"],
                        port.get("banner", "")
                    ])
            output_files["ports"] = ports_path
        
        return output_files
