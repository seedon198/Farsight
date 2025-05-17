"""Threat Intelligence module for FARSIGHT."""

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
        }
        
        # Initialize tasks list
        tasks = []
        
        # Always check PhoneBook.cz for leaked emails (public source)
        tasks.append(self._check_phonebook(domain))
        
        # For depth 2 or higher, try more checks
        if depth >= 2:
            # Add dark web check via API if available
            if is_api_configured("intelx"):
                tasks.append(self._check_intelx(domain, emails))
            
            # Check leaked credentials
            if emails and is_api_configured("leakpeek"):
                for email in emails:
                    tasks.append(self._check_leaked_credentials(email))
        
        # For comprehensive scan
        if depth >= 3:
            # Try to find documents and additional intelligence
            if is_api_configured("intelx"):
                tasks.append(self._check_documents_intelx(domain))
        
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
            logger.warning("IntelX API not configured. Skipping checks.")
            return
        
        try:
            # Get IntelX API handler
            handler = self.api_manager.get_handler("intelx")
            
            # Search for domain mentions
            search_data = {
                "term": domain,
                "buckets": ["pastes", "darknet"],
                "lookuplevel": 0,
                "maxresults": 20,
                "timeout": 10,
                "datefrom": "",
                "dateto": "",
                "sort": 4,  # Sort by date, newest first
                "media": 0,
                "terminate": []
            }
            
            # Start search
            search_response = await handler.post("intelligent/search", data=search_data)
            
            if not search_response or "id" not in search_response:
                logger.warning("Failed to initiate IntelX search")
                return
            
            # Get search ID
            search_id = search_response["id"]
            
            # Wait for results (with timeout)
            start_time = time.time()
            max_wait = 20  # seconds
            
            while time.time() - start_time < max_wait:
                # Check search status
                status_response = await handler.get(f"intelligent/search/result?id={search_id}&limit=20&offset=0")
                
                if status_response and "records" in status_response and status_response["records"]:
                    # Process results
                    self._process_intelx_results(status_response["records"], domain)
                    break
                
                # Wait before next check
                await asyncio.sleep(2)
            
            # Check for emails if provided
            if emails:
                for email in emails:
                    # Search for specific email
                    email_search = {
                        "term": email,
                        "buckets": ["leaks", "pastes", "darknet"],
                        "lookuplevel": 0,
                        "maxresults": 10,
                        "timeout": the10,
                        "sort": 4,
                        "media": 0,
                        "terminate": []
                    }
                    
                    # Start email search
                    email_response = await handler.post("intelligent/search", data=email_search)
                    
                    if not email_response or "id" not in email_response:
                        logger.warning(f"Failed to initiate IntelX search for {email}")
                        continue
                    
                    # Get search ID for email
                    email_search_id = email_response["id"]
                    
                    # Wait for email results (with timeout)
                    start_time = time.time()
                    
                    while time.time() - start_time < max_wait:
                        # Check search status
                        email_status = await handler.get(
                            f"intelligent/search/result?id={email_search_id}&limit=10&offset=0"
                        )
                        
                        if email_status and "records" in email_status and email_status["records"]:
                            # Process email results
                            leaked = any(record.get("bucket") == "leaks" for record in email_status["records"])
                            
                            if leaked:
                                self.results["credentials"].append({
                                    "email": email,
                                    "source": "IntelX",
                                    "date": time.strftime(
                                        "%Y-%m-%d", 
                                        time.localtime(email_status["records"][0].get("date", time.time()))
                                    ),
                                    "has_password": any("password" in record.get("snippet", "").lower() 
                                                     for record in email_status["records"]),
                                    "details": "Found in data leak"
                                })
                            break
                        
                        # Wait before next check
                        await asyncio.sleep(2)
        
        except Exception as e:
            logger.error(f"Error checking IntelX: {str(e)}")
    
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
            # Note: Real implementation would use the HIBP API with proper authentication
            # This is a simplified version that just indicates a need for API key
            
            logger.warning("HaveIBeenPwned API key required for production use")
            
            # For now, return a placeholder response
            return {
                "email": email,
                "found": False,
                "message": "HaveIBeenPwned API key required",
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
        # This is a placeholder for a full implementation
        # A real implementation would check various reputation services
        
        return {
            "email": email,
            "reputation": "unknown",
            "risk_score": 0,
            "last_seen": None,
        }
