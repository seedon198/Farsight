"""Typosquatting detection module for FARSIGHT."""

import asyncio
import time
import re
from typing import Dict, List, Set, Optional, Any, Tuple, Union
import socket
from urllib.parse import urlparse
import json

from farsight.utils.common import logger, retry
from farsight.utils.dns import DNSResolver
from farsight.config import get_config

# Force import dnstwist and handle it better to avoid false warnings
import importlib.util

# Check if dnstwist is available
dnstwist_spec = importlib.util.find_spec("dnstwist")
if dnstwist_spec is not None:
    import dnstwist.core
    DNSTWIST_AVAILABLE = True
else:
    logger.warning("dnstwist library not installed. Typosquatting detection will be limited.")
    DNSTWIST_AVAILABLE = False

# Check if rapidfuzz is available
rapidfuzz_spec = importlib.util.find_spec("rapidfuzz")
if rapidfuzz_spec is not None:
    import rapidfuzz.fuzz as fuzz
    RAPIDFUZZ_AVAILABLE = True
else:
    # Fall back to fuzzywuzzy if available
    fuzzywuzzy_spec = importlib.util.find_spec("fuzzywuzzy")
    if fuzzywuzzy_spec is not None:
        from fuzzywuzzy import fuzz
        RAPIDFUZZ_AVAILABLE = True
    else:
        logger.warning("No fuzzy matching library available. Similarity scoring will be limited.")
        RAPIDFUZZ_AVAILABLE = False


class TyposquatDetector:
    """Typosquatting detection class."""
    
    def __init__(self):
        """Initialize typosquat detector."""
        self.dns_resolver = DNSResolver()
        self.similarity_threshold = get_config("typosquat_threshold", 80)  # Default similarity threshold (0-100)
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        import aiohttp
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=get_config("timeout", 30))
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def detect(self, 
                    domain: str, 
                    depth: int = 1, 
                    check_dns: bool = True) -> Dict[str, Any]:
        """
        Detect typosquatting domains.
        
        Args:
            domain: Target domain
            depth: Scan depth level (1-3)
            check_dns: Whether to check if domains resolve
            
        Returns:
            Dictionary with typosquatting results
        """
        # Generate typo domains
        typo_domains = self._generate_typos(domain, depth)
        
        # Check for active domains
        active_domains = []
        if check_dns:
            active_domains = await self._check_domains_active(typo_domains)
        else:
            active_domains = typo_domains
        
        # Analyze active domains
        results = []
        if active_domains:
            results = await self._analyze_domains(domain, active_domains)
        
        return {
            "target_domain": domain,
            "total_generated": len(typo_domains),
            "total_active": len(active_domains),
            "similarity_threshold": self.similarity_threshold,
            "typosquats": results,
            "timestamp": time.time(),
        }
    
    def _generate_typos(self, domain: str, depth: int) -> List[str]:
        """
        Generate typosquatting domain variations.
        
        Args:
            domain: Target domain
            depth: Scan depth level (1-3)
            
        Returns:
            List of typosquatting domains
        """
        typo_domains = []
        
        if DNSTWIST_AVAILABLE:
            # Get domain parts
            domain_parts = domain.split('.')
            
            # Initialize DomainFuzz from dnstwist
            fuzzer = dnstwist.core.DomainFuzz(domain)
            
            # Generate based on depth
            fuzzer.generate()  # Basic typos
            
            # More comprehensive for deeper scans
            if depth >= 2:
                fuzzer.generate_homoglyphs()  # Homoglyphs
            
            if depth >= 3:
                fuzzer.generate_tld_swap()  # TLD swap
                fuzzer.generate_bit_squatting()  # Bit squatting
                fuzzer.generate_hyphenation()  # Hyphenation
                fuzzer.generate_insertion()  # Insertion
            
            # Extract domains from results
            for result in fuzzer.domains:
                if result['fuzzer'] != 'original':
                    typo_domains.append(result['domain-name'])
        
        else:
            # Fallback implementation if dnstwist is not available
            # Basic permutations only
            base_name, tld = domain.rsplit('.', 1)
            
            # Character replacement (common typos)
            replacements = {
                'a': ['e', 's', 'd', 'q', 'z', '4'],
                'b': ['v', 'g', 'h', 'n'],
                'c': ['x', 'v', 'd', 'f'],
                'd': ['s', 'e', 'f', 'c', 'x'],
                'e': ['r', 'w', 's', 'd', 'f', '3'],
                'f': ['d', 'r', 'g', 'v', 'c'],
                'g': ['f', 't', 'h', 'b', 'v'],
                'h': ['g', 'y', 'j', 'n', 'b'],
                'i': ['u', 'o', 'k', 'j', '1'],
                'j': ['h', 'u', 'k', 'n', 'm'],
                'k': ['j', 'i', 'l', 'm'],
                'l': ['k', 'o', 'p'],
                'm': ['n', 'j', 'k', 'l'],
                'n': ['b', 'h', 'j', 'm'],
                'o': ['i', 'p', 'l', 'k', '0'],
                'p': ['o', 'l'],
                'q': ['w', 'a'],
                'r': ['e', 't', 'f', 'd', '4'],
                's': ['a', 'w', 'e', 'd', 'x', 'z'],
                't': ['r', 'y', 'g', 'f', '5'],
                'u': ['y', 'i', 'j', 'h', '7'],
                'v': ['c', 'f', 'g', 'b'],
                'w': ['q', 's', 'e', '2'],
                'x': ['z', 's', 'd', 'c'],
                'y': ['t', 'u', 'h', 'g', '6'],
                'z': ['a', 's', 'x'],
                '0': ['o', '9'],
                '1': ['i', '2'],
                '2': ['1', '3', 'w'],
                '3': ['2', '4', 'e'],
                '4': ['3', '5', 'r'],
                '5': ['4', '6', 't'],
                '6': ['5', '7', 'y'],
                '7': ['6', '8', 'u'],
                '8': ['7', '9'],
                '9': ['8', '0'],
            }
            
            # Character replacement
            for i, char in enumerate(base_name):
                if char.lower() in replacements:
                    for replacement in replacements[char.lower()]:
                        new_name = base_name[:i] + replacement + base_name[i+1:]
                        typo_domains.append(f"{new_name}.{tld}")
            
            # Character omission
            for i in range(len(base_name)):
                new_name = base_name[:i] + base_name[i+1:]
                if new_name:  # Ensure name isn't empty
                    typo_domains.append(f"{new_name}.{tld}")
            
            # Adjacent character swap
            for i in range(len(base_name)-1):
                new_name = base_name[:i] + base_name[i+1] + base_name[i] + base_name[i+2:]
                typo_domains.append(f"{new_name}.{tld}")
            
            # Character duplication
            for i in range(len(base_name)):
                new_name = base_name[:i+1] + base_name[i] + base_name[i+1:]
                typo_domains.append(f"{new_name}.{tld}")
            
            # If depth is higher, add more typos
            if depth >= 2:
                # Character insertion
                for i in range(len(base_name)+1):
                    for c in 'abcdefghijklmnopqrstuvwxyz0123456789-':
                        new_name = base_name[:i] + c + base_name[i:]
                        typo_domains.append(f"{new_name}.{tld}")
                
                # TLD swap
                common_tlds = ['com', 'net', 'org', 'info', 'biz', 'io']
                for new_tld in common_tlds:
                    if new_tld != tld:
                        typo_domains.append(f"{base_name}.{new_tld}")
        
        # Remove duplicates and ensure original domain isn't included
        unique_domains = list(set(typo_domains))
        if domain in unique_domains:
            unique_domains.remove(domain)
        
        return unique_domains
    
    async def _check_domains_active(self, domains: List[str]) -> List[str]:
        """
        Check which domains are active (resolve to an IP).
        
        Args:
            domains: List of domains to check
            
        Returns:
            List of active domains
        """
        active_domains = []
        
        # Check DNS resolution for all domains
        concurrency = get_config("max_concurrent_requests", 20)
        dns_results = await self.dns_resolver.bulk_resolve(domains, ['A'], concurrency)
        
        # Filter to domains that resolved
        for check_domain, records in dns_results.items():
            if 'A' in records and records['A']:
                active_domains.append(check_domain)
        
        return active_domains
    
    async def _analyze_domains(self, 
                              original_domain: str, 
                              domains: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze potential typosquatting domains.
        
        Args:
            original_domain: Original domain
            domains: List of potential typosquatting domains
            
        Returns:
            List of typosquatting analysis results
        """
        results = []
        
        # Check DNS and HTTP for all domains
        dns_tasks = []
        http_tasks = []
        
        for domain in domains:
            dns_tasks.append(self._check_domain_dns(domain))
            if self.session:
                http_tasks.append(self._check_domain_http(domain))
        
        # Gather results
        dns_results = await asyncio.gather(*dns_tasks)
        http_results = await asyncio.gather(*http_tasks) if http_tasks else []
        
        # Process results
        for i, domain in enumerate(domains):
            dns_result = dns_results[i]
            http_result = http_results[i] if http_tasks else {"status": 0}
            
            # Calculate similarity score
            similarity = self._calculate_similarity(original_domain, domain)
            
            # Determine typo type
            typo_type = self._determine_typo_type(original_domain, domain)
            
            # Calculate risk score based on various factors
            risk_score = self._calculate_risk_score(
                original_domain,
                domain,
                similarity,
                dns_result.get("has_mx", False),
                http_result.get("status", 0) in range(200, 400),
                http_result.get("content_similarity", 0)
            )
            
            # Determine status
            status = "Suspicious" if risk_score > 70 else "Potential"
            
            # Add to results if risk score exceeds threshold
            if risk_score >= self.similarity_threshold:
                results.append({
                    "domain": domain,
                    "type": typo_type,
                    "status": status,
                    "risk_score": risk_score,
                    "has_dns": dns_result.get("has_a", False),
                    "has_mx": dns_result.get("has_mx", False),
                    "ip": dns_result.get("ip", None),
                    "http_status": http_result.get("status", 0),
                    "similarity": similarity,
                    "content_similarity": http_result.get("content_similarity", 0),
                    "title": http_result.get("title", None),
                })
        
        # Sort by risk score (highest first)
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return results
    
    async def _check_domain_dns(self, domain: str) -> Dict[str, Any]:
        """
        Check domain DNS records.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with DNS check results
        """
        result = {
            "has_a": False,
            "has_mx": False,
            "ip": None,
        }
        
        # Check A records
        a_records = await self.dns_resolver.resolve(domain, 'A')
        if a_records:
            result["has_a"] = True
            if "ip" in a_records[0]:
                result["ip"] = a_records[0]["ip"]
        
        # Check MX records
        mx_records = await self.dns_resolver.resolve(domain, 'MX')
        if mx_records:
            result["has_mx"] = True
        
        return result
    
    async def _check_domain_http(self, domain: str) -> Dict[str, Any]:
        """
        Check domain HTTP response.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with HTTP check results
        """
        result = {
            "status": 0,
            "title": None,
            "content_similarity": 0,
        }
        
        if not self.session:
            return result
        
        try:
            # Try HTTP and HTTPS
            for protocol in ["http", "https"]:
                url = f"{protocol}://{domain}"
                try:
                    async with self.session.get(
                        url, 
                        timeout=get_config("timeout", 10),
                        allow_redirects=True
                    ) as response:
                        result["status"] = response.status
                        
                        if response.status in range(200, 400):
                            # Get content type
                            content_type = response.headers.get("Content-Type", "")
                            
                            # Only process HTML content
                            if "text/html" in content_type:
                                content = await response.text()
                                
                                # Extract title
                                title_match = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                                if title_match:
                                    result["title"] = title_match.group(1).strip()
                            
                            return result
                except:
                    # If HTTP fails, try HTTPS and vice versa
                    continue
        except Exception as e:
            # Ignore errors
            pass
        
        return result
    
    def _calculate_similarity(self, original: str, typo: str) -> int:
        """
        Calculate string similarity between original and typo domain.
        
        Args:
            original: Original domain
            typo: Typo domain
            
        Returns:
            Similarity score (0-100)
        """
        # Extract base domains without TLD for better scoring
        original_base = original.split('.')[0]
        typo_base = typo.split('.')[0]
        
        # Use fuzzy matching library if available
        if RAPIDFUZZ_AVAILABLE:
            return int(fuzz.ratio(original_base, typo_base))
        
        # Fallback to basic similarity calculation
        # Levenshtein distance
        def levenshtein(s1, s2):
            if len(s1) < len(s2):
                return levenshtein(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        # Calculate Levenshtein distance
        distance = levenshtein(original_base, typo_base)
        
        # Convert to similarity score (0-100)
        max_len = max(len(original_base), len(typo_base))
        similarity = int((1 - (distance / max_len)) * 100) if max_len > 0 else 0
        
        return similarity
    
    def _determine_typo_type(self, original: str, typo: str) -> str:
        """
        Determine the type of typosquatting.
        
        Args:
            original: Original domain
            typo: Typo domain
            
        Returns:
            Typo type as string
        """
        original_parts = original.split('.')
        typo_parts = typo.split('.')
        
        # Check TLD swap
        if original_parts[0] == typo_parts[0] and original_parts[-1] != typo_parts[-1]:
            return "TLD swap"
        
        # Check for homoglyph (character replacement with similar looking)
        homoglyphs = {
            'a': ['4'],
            'b': ['6', '8'],
            'e': ['3'],
            'i': ['1', 'l'],
            'l': ['1', 'i'],
            'o': ['0'],
            's': ['5'],
            't': ['7'],
            'z': ['2'],
        }
        
        original_base = original_parts[0]
        typo_base = typo_parts[0]
        
        if len(original_base) == len(typo_base):
            diff_count = sum(1 for i in range(len(original_base)) if original_base[i] != typo_base[i])
            
            if diff_count == 1:
                # Check character replacement
                for i in range(len(original_base)):
                    if original_base[i] != typo_base[i]:
                        if original_base[i] in homoglyphs and typo_base[i] in homoglyphs[original_base[i]]:
                            return "Homoglyph"
                        else:
                            return "Character replacement"
            
            # Check adjacent character swap
            swaps = 0
            for i in range(len(original_base)-1):
                if original_base[i] == typo_base[i+1] and original_base[i+1] == typo_base[i]:
                    swaps += 1
            
            if swaps == 1:
                return "Character swap"
        
        # Check character omission (original is longer)
        if len(original_base) == len(typo_base) + 1:
            # Try to find position of omitted character
            for i in range(len(original_base)):
                omitted = original_base[:i] + original_base[i+1:]
                if omitted == typo_base:
                    return "Character omission"
        
        # Check character insertion (typo is longer)
        if len(typo_base) == len(original_base) + 1:
            # Try to find position of inserted character
            for i in range(len(typo_base)):
                without_insert = typo_base[:i] + typo_base[i+1:]
                if without_insert == original_base:
                    return "Character insertion"
        
        # Check character duplication
        for i in range(len(original_base)):
            duplicated = original_base[:i+1] + original_base[i] + original_base[i+1:]
            if duplicated == typo_base:
                return "Character duplication"
        
        # Check for hyphenation
        if "-" in typo_base and "-" not in original_base:
            return "Hyphenation"
        
        # Default
        return "Combination/Other"
    
    def _calculate_risk_score(self,
                            original: str,
                            typo: str,
                            similarity: int,
                            has_mx: bool,
                            has_web: bool,
                            content_similarity: int) -> int:
        """
        Calculate risk score for a typosquatting domain.
        
        Args:
            original: Original domain
            typo: Typo domain
            similarity: String similarity score
            has_mx: Whether domain has MX records
            has_web: Whether domain has a web server
            content_similarity: Content similarity score
            
        Returns:
            Risk score (0-100)
        """
        # Start with base score from string similarity
        score = similarity * 0.5  # Weight similarity at 50%
        
        # Add points for active services
        if has_mx:
            score += 15  # MX records indicate potential phishing risk
        
        if has_web:
            score += 10  # Web server indicates active use
        
        # Adjust based on content similarity
        score += content_similarity * 0.1  # Weight content similarity at 10%
        
        # Adjust based on typo type
        typo_type = self._determine_typo_type(original, typo)
        
        # Higher risk for homoglyphs and TLD swaps
        if typo_type == "Homoglyph":
            score += 10
        elif typo_type == "TLD swap":
            score += 8
        elif typo_type == "Character replacement":
            score += 5
        
        # Cap at 100
        return min(int(score), 100)
