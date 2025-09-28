"""Threat Intelligence module for FARSIGHT.

This module provides comprehensive threat intelligence gathering including
data leak detection, credential exposure monitoring, dark web mentions,
and email reputation analysis.
"""

import asyncio
import re
import time
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from bs4 import BeautifulSoup
import json
import urllib.parse

from farsight.utils.common import logger, retry
from farsight.utils.api_handler import APIManager
from farsight.config import get_config, is_api_configured


class ThreatIntel:
    """Threat Intelligence class for finding data leaks and breaches."""
    
    def __init__(self, api_manager: Optional[APIManager] = None):
        """
        Initialize threat intelligence module.
        
        Args:
            api_manager: API manager for making API requests (optional)
        """
        self.api_manager = api_manager or APIManager()
        self.session = None
        self.results = {
            "leaks": [],
            "dark_web": [],
            "credentials": [],
        }
    
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
    
    async def gather_intelligence(self, 
                                 domain: str, 
                                 emails: Optional[List[str]] = None, 
                                 depth: int = 1) -> Dict[str, Any]:
        """
        Gather threat intelligence for a domain and optional email list.
        
        Args:
            domain: Target domain
            emails: Optional list of email addresses to check
            depth: Scan depth level (1-3)
            
        Returns:
            Dictionary with threat intelligence results
        """
        # Reset results
        self.results = {
            "leaks": [],
            "dark_web": [],
            "credentials": [],
            "email_reputation": [],
        }
        
        # Initialize tasks list
        tasks = []
        
        # Always check PhoneBook.cz for leaked emails (public source)
        tasks.append(self._check_phonebook(domain))
        
        # Always use alternative dark web monitoring method when IntelX API is not available
        if not is_api_configured("intelx"):
            tasks.append(self._check_dark_web_alternative(domain, emails))
        
        # For depth 2 or higher, try more checks
        if depth >= 2:
            # Add dark web check via API if available
            if is_api_configured("intelx"):
                tasks.append(self._check_intelx(domain, emails))
            
            # Check leaked credentials
            if emails and is_api_configured("leakpeek"):
                for email in emails:
                    tasks.append(self._check_leaked_credentials(email))
            
            # Check email reputation for all email addresses
            if emails:
                for email in emails:
                    # Add email reputation analysis for each email
                    email_rep_task = self.get_email_reputation(email)
                    tasks.append(email_rep_task)
        
        # For comprehensive scan
        if depth >= 3:
            # Try to find documents and additional intelligence
            if is_api_configured("intelx"):
                tasks.append(self._check_documents_intelx(domain))
            
            # If domain has emails but they weren't provided, try to use HIBP alternative check
            domain_emails = []
            for leak in self.results["leaks"]:
                if "emails" in leak:
                    domain_emails.extend(leak["emails"])
            
            if domain_emails and not emails:
                for email in domain_emails[:3]:  # Limit to first 3 to avoid overload
                    tasks.append(self.check_haveibeenpwned(email))
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)
        
        # Process and deduplicate results
        unique_emails = set()
        for leak in self.results["leaks"]:
            if "emails" in leak:
                for email in leak["emails"]:
                    unique_emails.add(email)
        
        for cred in self.results["credentials"]:
            if "email" in cred:
                unique_emails.add(cred["email"])
        
        # Return processed results
        return {
            "target_domain": domain,
            "leaks": self.results["leaks"],
            "dark_web": self.results["dark_web"],
            "credentials": self.results["credentials"],
            "email_reputation": self.results["email_reputation"],
            "unique_emails_found": list(unique_emails),
            "total_emails_found": len(unique_emails),
            "total_leaks": len(self.results["leaks"]),
            "total_dark_web": len(self.results["dark_web"]),
            "total_credentials": len(self.results["credentials"]),
            "timestamp": time.time(),
        }
    
    @retry(max_retries=2, delay=1.0, backoff=2.0)
    async def _check_phonebook(self, domain: str) -> None:
        """
        Check PhoneBook.cz for leaked emails.
        
        Args:
            domain: Target domain
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return
        
        try:
            # PhoneBook.cz direct API access is limited, use scraping as fallback
            encoded_domain = urllib.parse.quote(domain)
            url = f"https://phonebook.cz/search.php?q=%40{encoded_domain}"
            
            headers = {
                "User-Agent": get_config("user_agent"),
                "Accept": "text/html,application/xhtml+xml,application/xml",
                "Referer": "https://phonebook.cz/",
            }
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    # Extract emails from the page
                    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.' + domain, html)
                    unique_emails = list(set(emails))
                    
                    if unique_emails:
                        self.results["leaks"].append({
                            "source": "phonebook.cz",
                            "type": "email_leak",
                            "date": "Unknown",  # PhoneBook doesn't provide dates
                            "emails": unique_emails,
                            "count": len(unique_emails),
                            "details": f"Found {len(unique_emails)} email addresses from {domain}"
                        })
                        
                        logger.info(f"Found {len(unique_emails)} emails from PhoneBook.cz")
                else:
                    logger.warning(f"PhoneBook.cz returned status {response.status}")
        except Exception as e:
            logger.error(f"Error checking PhoneBook.cz: {str(e)}")
    
    async def _check_intelx(self, domain: str, emails: Optional[List[str]] = None) -> None:
        """
        Check IntelX for leaks and dark web mentions.
        
        Args:
            domain: Target domain
            emails: Optional list of email addresses to check
        """
        if not is_api_configured("intelx"):
            # Fallback to alternative dark web monitoring method when API is not available
            await self._check_dark_web_alternative(domain, emails)
            return
        
        try:
            # Get IntelX API handler
            handler = self.api_manager.get_handler("intelx")
            
            # Search for the domain in leaked data
            search_params = {
                "term": domain,
                "maxresults": 20,  # Increased from 10 to 20 for better coverage
                "media": 0,  # All media types
                "sort": 4,    # Sort by date (newest first)
                "terminate": [],  # No reasons to terminate
            }
            
            # Run search request
            search_resp = await handler.post("intelligent/search", json=search_params)
            
            if search_resp and "id" in search_resp:
                search_id = search_resp["id"]
                
                # Wait for search to complete
                max_attempts = 5
                for attempt in range(max_attempts):
                    # Check search status
                    result_resp = await handler.get(f"intelligent/search/result?id={search_id}&limit=20")
                    
                    if result_resp and "records" in result_resp and result_resp["records"]:
                        # Process search results
                        await self._process_intelx_results(result_resp["records"], domain)
                        break
                    
                    # Wait before retrying
                    await asyncio.sleep(2)
            
            # If emails provided, check each one
            if emails:
                for email in emails:
                    # Search for the email in leaked data
                    email_search = {
                        "term": email,
                        "maxresults": 10,  # Increased from 5 to 10 for better coverage
                        "media": 0,  # All media types
                        "sort": 4,    # Sort by date (newest first)
                        "terminate": [],  # No reasons to terminate
                    }
                    
                    # Run search request
                    email_resp = await handler.post("intelligent/search", json=email_search)
                    
                    if email_resp and "id" in email_resp:
                        email_search_id = email_resp["id"]
                        
                        # Wait for search to complete
                        max_attempts = 3
                        for attempt in range(max_attempts):
                            # Check search status
                            email_result = await handler.get(
                                f"intelligent/search/result?id={email_search_id}&limit=10"
                            )
                            
                            if email_result and "records" in email_result and email_result["records"]:
                                # Process search results - add more detailed information
                                for record in email_result["records"]:
                                    if "name" in record and "bucket" in record:
                                        name = record["name"]
                                        bucket = record["bucket"]
                                        added = record.get("added", "unknown")
                                        media_type = record.get("media", 0)
                                        
                                        # Determine the type of leak based on media type
                                        leak_type = "unknown"
                                        if media_type == 1:
                                            leak_type = "text_leak"
                                        elif media_type == 2:
                                            leak_type = "credential_leak"
                                        elif media_type == 8:
                                            leak_type = "database_dump"
                                        elif media_type == 13:
                                            leak_type = "forum_data"
                                        elif media_type == 15:
                                            leak_type = "dark_web_market"
                                        
                                        # Add more detailed risk assessment based on the source
                                        risk_level = "medium"
                                        if "password" in bucket.lower() or "credentials" in bucket.lower():
                                            risk_level = "high"
                                        if "darkweb" in bucket.lower() or "market" in bucket.lower():
                                            risk_level = "critical"
                                        
                                        self.results["dark_web"].append({
                                            "type": leak_type,
                                            "target": email,
                                            "source": bucket,
                                            "date": added,
                                            "risk_level": risk_level,
                                            "details": f"Email found in {name}"
                                        })
                                
                                break
                            
                            # Wait before retrying
                            await asyncio.sleep(1)
        
        except Exception as e:
            logger.error(f"Error checking IntelX: {str(e)}")
            # Fall back to alternative method if IntelX fails
            await self._check_dark_web_alternative(domain, emails)

    async def _check_dark_web_alternative(self, domain: str, emails: Optional[List[str]] = None) -> None:
        """
        Alternative method to check for dark web mentions when IntelX API is not available.
        
        Args:
            domain: Target domain
            emails: Optional list of email addresses to check
        """
        logger.info(f"Using alternative dark web monitoring method for {domain}")
        
        try:
            if not self.session:
                logger.error("Session not initialized. Use async with context.")
                return
            
            # Check known leak databases using pattern matching
            known_leaks = [
                # Format: (leak_name, leak_date, leak_type, affected_entities)
                ("Collection #1", "2019-01-17", "credential_leak", ["gmail.com", "yahoo.com", "hotmail.com"]),
                ("LinkedIn Breach", "2012-06-05", "database_dump", ["linkedin.com"]),
                ("Adobe Breach", "2013-10-04", "credential_leak", ["adobe.com"]),
                ("Dropbox Breach", "2012-07-01", "credential_leak", ["dropbox.com"]),
                ("Facebook Breach", "2019-04-03", "personal_info", ["facebook.com"]),
                ("Sony Pictures", "2014-11-24", "corporate_data", ["sony.com", "spe.sony.com"]),
                ("Ashley Madison", "2015-07-20", "personal_info", ["ashleymadison.com"]),
                ("MySpace", "2016-05-31", "credential_leak", ["myspace.com"]),
                ("Equifax", "2017-09-07", "financial_data", ["equifax.com"]),
                ("Marriott", "2018-11-30", "personal_info", ["marriott.com", "starwoodhotels.com"]),
            ]
            
            # Check domain against known leaks
            for leak_name, leak_date, leak_type, affected in known_leaks:
                for entity in affected:
                    if domain.lower() == entity or domain.lower().endswith(f".{entity}"):
                        self.results["dark_web"].append({
                            "type": leak_type,
                            "target": domain,
                            "source": "Historical Breach Database",
                            "date": leak_date,
                            "risk_level": "medium",
                            "confidence": "medium",
                            "details": f"Domain potentially affected by {leak_name} breach",
                            "note": "Based on domain pattern matching. For confirmed matches, use IntelX API."
                        })
            
            # Check emails if provided
            if emails:
                for email in emails:
                    email_domain = email.split('@')[-1] if '@' in email else None
                    if not email_domain:
                        continue
                    
                    # Check each email domain against known leaks
                    for leak_name, leak_date, leak_type, affected in known_leaks:
                        for entity in affected:
                            if email_domain.lower() == entity or email_domain.lower().endswith(f".{entity}"):
                                self.results["dark_web"].append({
                                    "type": leak_type,
                                    "target": email,
                                    "source": "Historical Breach Database",
                                    "date": leak_date,
                                    "risk_level": "medium",
                                    "confidence": "low",
                                    "details": f"Email potentially affected by {leak_name} breach",
                                    "note": "Based on email domain pattern matching. For confirmed matches, use IntelX API."
                                })
                    
                    # Check for common patterns that indicate high-risk emails
                    username = email.split('@')[0]
                    high_risk_patterns = ["admin", "root", "webmaster", "security", "ceo", "finance"]
                    
                    for pattern in high_risk_patterns:
                        if pattern in username.lower():
                            self.results["dark_web"].append({
                                "type": "high_value_target",
                                "target": email,
                                "source": "Pattern Analysis",
                                "date": time.strftime("%Y-%m-%d"),
                                "risk_level": "high",
                                "confidence": "medium",
                                "details": f"High-value email pattern detected ({pattern})",
                                "note": "High-privilege accounts are prime targets for threat actors"
                            })
                            break
        
        except Exception as e:
            logger.error(f"Error in alternative dark web check: {str(e)}")
    
    def _process_intelx_results(self, records: List[Dict[str, Any]], domain: str) -> None:
        """
        Process IntelX search results.
        
        Args:
            records: List of IntelX records
            domain: Target domain
        """
        for record in records:
            # Get basic info
            bucket = record.get("bucket", "unknown")
            title = record.get("name", "Untitled")
            date_epoch = record.get("date", 0)
            date_str = time.strftime("%Y-%m-%d", time.localtime(date_epoch)) if date_epoch else "Unknown"
            
            snippet = record.get("snippet", "")
            
            # Process based on bucket type
            if bucket == "pastes":
                self.results["leaks"].append({
                    "source": "IntelX (Paste)",
                    "type": "paste",
                    "date": date_str,
                    "title": title,
                    "details": snippet[:100] + "..." if len(snippet) > 100 else snippet
                })
            elif bucket == "darknet":
                self.results["dark_web"].append({
                    "source": "Dark Web",
                    "date": date_str,
                    "title": title,
                    "text": snippet[:100] + "..." if len(snippet) > 100 else snippet
                })
            elif bucket == "leaks":
                # Extract emails if any
                emails = re.findall(r'[\w\.-]+@[\w\.-]+\.' + domain, snippet)
                unique_emails = list(set(emails))
                
                self.results["leaks"].append({
                    "source": "IntelX (Leak)",
                    "type": "data_leak",
                    "date": date_str,
                    "title": title,
                    "emails": unique_emails,
                    "count": len(unique_emails),
                    "details": snippet[:100] + "..." if len(snippet) > 100 else snippet
                })
    
    async def _check_documents_intelx(self, domain: str) -> None:
        """
        Check IntelX for leaked documents related to the domain.
        
        Args:
            domain: Target domain
        """
        if not is_api_configured("intelx"):
            return
        
        try:
            # Get IntelX API handler
            handler = self.api_manager.get_handler("intelx")
            
            # Search for documents
            search_data = {
                "term": domain,
                "buckets": ["documents"],
                "lookuplevel": 0,
                "maxresults": 10,
                "timeout": 10,
                "datefrom": "",
                "dateto": "",
                "sort": 4,
                "media": 0,
                "terminate": []
            }
            
            # Start search
            search_response = await handler.post("intelligent/search", data=search_data)
            
            if not search_response or "id" not in search_response:
                return
            
            # Get search ID
            search_id = search_response["id"]
            
            # Wait for results (with timeout)
            start_time = time.time()
            max_wait = 20  # seconds
            
            while time.time() - start_time < max_wait:
                # Check search status
                status_response = await handler.get(f"intelligent/search/result?id={search_id}&limit=10&offset=0")
                
                if status_response and "records" in status_response and status_response["records"]:
                    # Process document results
                    for record in status_response["records"]:
                        title = record.get("name", "Untitled Document")
                        date_epoch = record.get("date", 0)
                        date_str = time.strftime("%Y-%m-%d", time.localtime(date_epoch)) if date_epoch else "Unknown"
                        
                        self.results["leaks"].append({
                            "source": "IntelX (Document)",
                            "type": "document",
                            "date": date_str,
                            "title": title,
                            "details": f"Document: {title}"
                        })
                    
                    break
                
                # Wait before next check
                await asyncio.sleep(2)
        
        except Exception as e:
            logger.error(f"Error checking IntelX for documents: {str(e)}")
    
    async def _check_leaked_credentials(self, email: str) -> None:
        """
        Check LeakPeek API for leaked credentials.
        
        Args:
            email: Email address to check
        """
        if not is_api_configured("leakpeek"):
            return
        
        try:
            # Get LeakPeek API handler
            handler = self.api_manager.get_handler("leakpeek")
            
            # Query for leaked credentials
            response = await handler.get(f"search/email/{email}")
            
            if response and "found" in response and response["found"]:
                # Extract breach information
                sources = []
                has_password = False
                latest_date = None
                
                if "breaches" in response:
                    for breach in response["breaches"]:
                        sources.append(breach.get("name", "Unknown"))
                        
                        # Check if password is exposed
                        if "password" in breach:
                            has_password = True
                        
                        # Track latest breach date
                        breach_date = breach.get("date")
                        if breach_date:
                            if not latest_date or breach_date > latest_date:
                                latest_date = breach_date
                
                self.results["credentials"].append({
                    "email": email,
                    "source": ", ".join(sources) if sources else "Unknown",
                    "date": latest_date or "Unknown",
                    "has_password": has_password,
                    "details": f"Found in {len(sources)} data breach(es)"
                })
                
                logger.info(f"Found leaked credentials for {email}")
        
        except Exception as e:
            logger.error(f"Error checking LeakPeek API: {str(e)}")
    
    async def check_haveibeenpwned(self, email: str) -> Dict[str, Any]:
        """
        Alternative method to check email against public sources.
        
        Args:
            email: Email address to check
            
        Returns:
            Dictionary with breach results
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return {"email": email, "found": False}
        
        try:
            # Check if HIBP API key is configured
            if is_api_configured("hibp"):
                # Get HIBP API handler
                handler = self.api_manager.get_handler("hibp")
                
                # Query for breaches
                headers = {"hibp-api-key": get_config("hibp_api_key", ""), "User-Agent": "Farsight Framework"}
                response = await handler.get(f"breachedaccount/{email}", headers=headers)
                
                if response and isinstance(response, list) and len(response) > 0:
                    breaches = []
                    for breach in response:
                        breaches.append({
                            "name": breach.get("Name", "Unknown"),
                            "domain": breach.get("Domain", "Unknown"),
                            "breach_date": breach.get("BreachDate", "Unknown"),
                            "pwn_count": breach.get("PwnCount", 0),
                            "data_classes": breach.get("DataClasses", [])
                        })
                    
                    return {
                        "email": email,
                        "found": True,
                        "breach_count": len(breaches),
                        "breaches": breaches
                    }
                
                return {
                    "email": email,
                    "found": False,
                    "breach_count": 0,
                }
            
            # Fallback to alternative method when API key is not available
            # Using a correlation approach based on common breach data patterns
            logger.warning("HaveIBeenPwned API key not configured. Using alternative check method.")
            
            domain = email.split('@')[-1] if '@' in email else None
            if not domain:
                return {"email": email, "found": False}
            
            # List of known major breaches to check against
            known_breaches = [
                # Format: (domain, breach_name, breach_date, affected_accounts)
                ("linkedin.com", "LinkedIn", "2012-05-05", 164611595),
                ("adobe.com", "Adobe", "2013-10-04", 152445165),
                ("yahoo.com", "Yahoo", "2013-08-01", 3000000000),
                ("myspace.com", "MySpace", "2008-07-01", 359420698),
                ("tumblr.com", "Tumblr", "2013-02-28", 65469298),
                ("sony.com", "Sony", "2011-06-02", 37103500),
                ("dropbox.com", "Dropbox", "2012-07-01", 68648009),
                ("ebay.com", "eBay", "2014-05-21", 145000000),
            ]
            
            # Check if the domain matches any known breaches
            potential_breaches = []
            for breach_domain, name, date, count in known_breaches:
                if domain.lower() == breach_domain or domain.lower().endswith(f".{breach_domain}"):
                    potential_breaches.append({
                        "name": name,
                        "domain": breach_domain,
                        "breach_date": date,
                        "pwn_count": count,
                        "confidence": "medium",
                        "note": "Domain correlation only, not a confirmed match. Verification requires API key."
                    })
            
            if potential_breaches:
                return {
                    "email": email,
                    "found": True,
                    "breach_count": len(potential_breaches),
                    "breaches": potential_breaches,
                    "note": "Potential matches based on domain only. For confirmed matches, configure the HIBP API key."
                }
            
            # Return default response
            return {
                "email": email,
                "found": False,
                "message": "No matches found, but full verification requires HIBP API key",
            }
        
        except Exception as e:
            logger.error(f"Error checking HaveIBeenPwned: {str(e)}")
            return {"email": email, "found": False, "error": str(e)}
    
    async def get_email_reputation(self, email: str) -> Dict[str, Any]:
        """
        Get email reputation from various sources.
        
        Args:
            email: Email address to check
            
        Returns:
            Dictionary with email reputation info
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return {"email": email, "reputation": "unknown", "risk_score": 0}
        
        try:
            # Check domain reputation from email
            domain = email.split('@')[-1] if '@' in email else None
            domain_reputation = {"risk": "unknown"}
            
            if domain:
                # Check domain age and registration info
                try:
                    import whois
                    domain_info = whois.whois(domain)
                    creation_date = domain_info.creation_date
                    if creation_date:
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]  # Use first date if multiple
                        
                        from datetime import datetime
                        age_days = (datetime.now() - creation_date).days
                        domain_reputation["age_days"] = age_days
                        
                        # Domains less than 30 days old are suspicious
                        if age_days < 30:
                            domain_reputation["risk"] = "high"
                        elif age_days < 90:
                            domain_reputation["risk"] = "medium"
                        else:
                            domain_reputation["risk"] = "low"
                except Exception as e:
                    logger.warning(f"Could not check domain age: {str(e)}")
                
                # Check for disposable email domains
                disposable_domains = [
                    "10minutemail.com", "guerrillamail.com", "mailinator.com", "temp-mail.org",
                    "fakeinbox.com", "tempinbox.com", "sharklasers.com", "yopmail.com",
                    "trashmail.com", "getnada.com", "dispostable.com", "tempmailaddress.com"
                ]
                
                if domain.lower() in disposable_domains:
                    domain_reputation["disposable"] = True
                    domain_reputation["risk"] = "high"
                else:
                    domain_reputation["disposable"] = False
            
            # Calculate risk score based on several factors
            risk_factors = {
                "suspicious_patterns": False,
                "common_spam_patterns": False,
                "numeric_heavy": False
            }
            
            # Check for suspicious patterns in email
            username = email.split('@')[0] if '@' in email else email
            
            # Excessive numbers often indicate spam/throwaway accounts
            if sum(c.isdigit() for c in username) > len(username) * 0.5:
                risk_factors["numeric_heavy"] = True
            
            # Common spam patterns
            spam_patterns = ["admin", "info", "sales", "support", "noreply", "contact"]
            if username.lower() in spam_patterns:
                risk_factors["common_spam_patterns"] = True
            
            # Calculate overall risk score (0-100)
            risk_score = 0
            
            if domain_reputation["risk"] == "high":
                risk_score += 40
            elif domain_reputation["risk"] == "medium":
                risk_score += 20
            
            if domain_reputation.get("disposable", False):
                risk_score += 30
            
            if risk_factors["numeric_heavy"]:
                risk_score += 15
            
            if risk_factors["common_spam_patterns"]:
                risk_score += 10
            
            # Determine reputation based on risk score
            reputation = "unknown"
            if risk_score >= 70:
                reputation = "high risk"
            elif risk_score >= 40:
                reputation = "medium risk"
            elif risk_score >= 10:
                reputation = "low risk"
            else:
                reputation = "good"
            
            # Create the result
            result = {
                "email": email,
                "reputation": reputation,
                "risk_score": risk_score,
                "domain_info": domain_reputation,
                "risk_factors": risk_factors,
                "last_checked": time.time(),
            }
            
            # Store in results list if available
            if hasattr(self, 'results') and "email_reputation" in self.results:
                self.results["email_reputation"].append(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking email reputation: {str(e)}")
            return {
                "email": email,
                "reputation": "unknown",
                "risk_score": 0,
                "error": str(e)
            }
