"""DNS utility functions for FARSIGHT.

This module provides DNS resolution, subdomain enumeration, and port scanning
capabilities with robust error handling and performance optimizations.
"""

import asyncio
import dns.resolver
import socket
from typing import Dict, List, Set, Optional, Any, Tuple, Union
import ipaddress
import random
import time

from farsight.utils.common import logger, retry
from farsight.config import get_config


class DNSResolver:
    """Async DNS resolver with failover support."""
    
    def __init__(self, 
                 nameservers: Optional[List[str]] = None,
                 timeout: Optional[float] = None,
                 max_retries: int = 3):
        """
        Initialize DNS resolver.
        
        Args:
            nameservers: List of DNS servers to use
            timeout: Timeout for DNS queries in seconds
            max_retries: Maximum number of retries for failed queries
        """
        self.nameservers = nameservers or [
            get_config("dns_resolver", "1.1.1.1"),
            "8.8.8.8",  # Google DNS as backup
            "9.9.9.9",  # Quad9 as tertiary
        ]
        self.timeout = timeout or get_config("timeout", 5)
        self.max_retries = max_retries
        self.resolver = dns.resolver.Resolver()
        # Set nameservers directly as strings, not as packed IP addresses
        self.resolver.nameservers = [
            ns for ns in self.nameservers if self._is_valid_ip(ns)
        ]
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2  # Total query lifetime
        
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @retry(max_retries=3, delay=1.0, backoff=2.0)
    async def resolve(self, 
                     domain: str, 
                     record_type: str = 'A') -> List[Dict[str, Any]]:
        """
        Resolve DNS records for a domain.
        
        Args:
            domain: Domain to resolve
            record_type: DNS record type (A, AAAA, MX, CNAME, TXT, etc.)
            
        Returns:
            List of DNS records
        """
        loop = asyncio.get_event_loop()
        
        try:
            # Run DNS query in thread pool to avoid blocking
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, record_type)
            )
            
            records = []
            
            for ans in answers:
                record = {"type": record_type}
                
                # Handle different record types
                if record_type == 'A' or record_type == 'AAAA':
                    record['ip'] = ans.address
                elif record_type == 'MX':
                    record['priority'] = ans.preference
                    record['exchange'] = str(ans.exchange)
                elif record_type == 'CNAME':
                    record['target'] = str(ans.target)
                elif record_type == 'TXT':
                    record['txt'] = str(ans)
                elif record_type == 'NS':
                    record['nameserver'] = str(ans.target)
                elif record_type == 'SOA':
                    record['mname'] = str(ans.mname)
                    record['rname'] = str(ans.rname)
                    record['serial'] = ans.serial
                    record['refresh'] = ans.refresh
                    record['retry'] = ans.retry
                    record['expire'] = ans.expire
                    record['minimum'] = ans.minimum
                else:
                    record['value'] = str(ans)
                
                records.append(record)
            
            return records
        except dns.resolver.NXDOMAIN:
            logger.debug(f"NXDOMAIN: {domain} has no {record_type} record")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"NoAnswer: {domain} has no {record_type} record")
            return []
        except dns.resolver.Timeout:
            logger.debug(f"Timeout resolving {record_type} record for {domain}")
            raise  # Let retry decorator handle this
        except Exception as e:
            logger.error(f"Error resolving {record_type} record for {domain}: {str(e)}")
            return []
    
    async def bulk_resolve(self, 
                          domains: List[str], 
                          record_types: List[str] = ['A'],
                          concurrency: Optional[int] = None) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """
        Resolve multiple domains concurrently.
        
        Args:
            domains: List of domains to resolve
            record_types: List of record types to resolve
            concurrency: Maximum number of concurrent DNS queries
            
        Returns:
            Dictionary of domains with their DNS records
        """
        if not domains:
            return {}
        
        if not concurrency:
            concurrency = get_config("max_concurrent_requests", 10)
        
        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(concurrency)
        
        async def _resolve_with_limit(domain: str, record_type: str) -> Tuple[str, str, List[Dict[str, Any]]]:
            """Resolve with concurrency limit."""
            async with semaphore:
                # Add some jitter to avoid hammering DNS servers
                await asyncio.sleep(random.uniform(0.01, 0.1))
                result = await self.resolve(domain, record_type)
                return domain, record_type, result
        
        # Create tasks for all domain/record type combinations
        tasks = []
        for domain in domains:
            for record_type in record_types:
                tasks.append(_resolve_with_limit(domain, record_type))
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        dns_records = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error in bulk DNS resolution: {str(result)}")
                continue
            
            domain, record_type, records = result
            
            if domain not in dns_records:
                dns_records[domain] = {}
            
            dns_records[domain][record_type] = records
        
        return dns_records


class PortScanner:
    """Asynchronous port scanner using asyncio and socket."""
    
    def __init__(self, 
                 timeout: Optional[float] = None,
                 max_concurrent_scans: Optional[int] = None):
        """
        Initialize port scanner.
        
        Args:
            timeout: Timeout for port scanning in seconds
            max_concurrent_scans: Maximum number of concurrent port scans
        """
        self.timeout = timeout or get_config("port_scan_timeout", 2)
        self.max_concurrent_scans = max_concurrent_scans or get_config("max_concurrent_requests", 100)
    
    async def scan_port(self, 
                       target: str, 
                       port: int) -> Dict[str, Any]:
        """
        Scan a single port on a target.
        
        Args:
            target: Target IP or hostname
            port: Port to scan
            
        Returns:
            Dictionary with scan results
        """
        result = {
            "port": port,
            "open": False,
            "banner": None,
        }
        
        try:
            # Create future with timeout
            connect_future = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(connect_future, timeout=self.timeout)
            
            # Port is open
            result["open"] = True
            
            try:
                # Try to read banner (with shorter timeout)
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if banner_data:
                    result["banner"] = banner_data.decode('utf-8', errors='ignore').strip()
            except (asyncio.TimeoutError, UnicodeDecodeError):
                # No banner or couldn't decode
                pass
            finally:
                writer.close()
                await writer.wait_closed()
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port is closed/filtered or unreachable
            pass
        except Exception as e:
            logger.error(f"Error scanning port {port} on {target}: {str(e)}")
        
        return result
    
    async def scan_ports(self, 
                        target: str, 
                        ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Scan multiple ports on a target.
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            
        Returns:
            Dictionary with scan results
        """
        if not ports:
            # Use default port list from config
            ports = get_config("default_ports", [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
            ])
        
        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        
        async def _scan_with_limit(p: int) -> Dict[str, Any]:
            """Scan port with concurrency limit."""
            async with semaphore:
                # Add some jitter to avoid overwhelming target
                await asyncio.sleep(random.uniform(0.01, 0.1))
                return await self.scan_port(target, p)
        
        # Scan all ports concurrently
        scan_tasks = [_scan_with_limit(port) for port in ports]
        results = await asyncio.gather(*scan_tasks)
        
        # Filter to only open ports
        open_ports = [r for r in results if r["open"]]
        
        return {
            "target": target,
            "timestamp": time.time(),
            "total_ports": len(ports),
            "open_ports": len(open_ports),
            "ports": open_ports,
        }


async def is_domain_alive(domain: str) -> bool:
    """
    Check if a domain resolves to a valid IP address.
    
    Args:
        domain: Domain to check
        
    Returns:
        True if domain resolves, False otherwise
    """
    resolver = DNSResolver()
    records = await resolver.resolve(domain)
    return len(records) > 0


async def check_spf_dmarc(domain: str) -> Dict[str, Any]:
    """
    Check SPF and DMARC records for a domain.
    
    Args:
        domain: Domain to check
        
    Returns:
        Dictionary with SPF and DMARC information
    """
    resolver = DNSResolver()
    
    # Check SPF record (TXT record with specific format)
    spf_records = await resolver.resolve(domain, 'TXT')
    spf_found = False
    spf_record = None
    
    for record in spf_records:
        if 'txt' in record and record['txt'].startswith('"v=spf1'):
            spf_found = True
            spf_record = record['txt'].strip('"')
            break
    
    # Check DMARC record
    dmarc_records = await resolver.resolve(f"_dmarc.{domain}", 'TXT')
    dmarc_found = False
    dmarc_record = None
    
    for record in dmarc_records:
        if 'txt' in record and record['txt'].startswith('"v=DMARC1'):
            dmarc_found = True
            dmarc_record = record['txt'].strip('"')
            break
    
    return {
        "domain": domain,
        "spf": {
            "found": spf_found,
            "record": spf_record,
        },
        "dmarc": {
            "found": dmarc_found,
            "record": dmarc_record,
        },
    }


async def enum_subdomains(domain: str, 
                         wordlist: Optional[List[str]] = None, 
                         concurrency: Optional[int] = None) -> List[str]:
    """
    Enumerate subdomains using DNS brute force.
    
    Args:
        domain: Domain to enumerate
        wordlist: List of subdomain prefixes to try
        concurrency: Maximum number of concurrent DNS queries
        
    Returns:
        List of discovered subdomains
    """
    if not wordlist:
        # Use a small default wordlist
        # In production, this would be loaded from a file
        wordlist = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "admin", "dev", "staging", "test", "portal",
            "api", "apps", "auth", "beta", "cdn", "cloud", "cms", "connect",
            "demo", "direct", "docs", "exchange", "files", "help", "host",
            "intranet", "login", "mobile", "new", "news", "old", "owa", "shop",
            "sites", "sso", "staff", "store", "support", "web"
        ]
    
    # Generate list of full domain names to check
    domains_to_check = [f"{sub}.{domain}" for sub in wordlist]
    
    # Resolve all domains
    resolver = DNSResolver()
    dns_results = await resolver.bulk_resolve(domains_to_check, ['A'], concurrency)
    
    # Filter to domains that resolved
    discovered = []
    for check_domain, records in dns_results.items():
        if 'A' in records and records['A']:
            discovered.append(check_domain)
    
    return discovered
