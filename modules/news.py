"""News monitoring module for FARSIGHT."""

import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import re

from farsight.utils.common import logger, retry
from farsight.config import get_config

try:
    from gnews import GNews
    GNEWS_AVAILABLE = True
except ImportError:
    logger.warning("gnews library not installed. News monitoring will use alternative methods.")
    GNEWS_AVAILABLE = False


class NewsMonitor:
    """News monitoring class for tracking mentions of a target in news articles."""
    
    def __init__(self):
        """Initialize news monitor."""
        self.session = None
        self.results = {
            "articles": [],
        }
        self.results_limit = get_config("news_results_limit", 10)
    
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
    
    async def monitor(self, 
                     target: str, 
                     days: int = 30, 
                     max_results: Optional[int] = None) -> Dict[str, Any]:
        """
        Monitor news for mentions of a target.
        
        Args:
            target: Target domain or organization name
            days: Number of days to look back
            max_results: Maximum number of results to return
            
        Returns:
            Dictionary with news monitoring results
        """
        # Reset results
        self.results = {
            "articles": [],
        }
        
        if not max_results:
            max_results = self.results_limit
        
        if GNEWS_AVAILABLE:
            await self._monitor_with_gnews(target, days, max_results)
        else:
            # Fallback to alternative method
            await self._monitor_alternative(target, days, max_results)
        
        # Process and sort articles by date (newest first)
        self.results["articles"].sort(
            key=lambda x: datetime.strptime(x.get("published", "2000-01-01"), "%Y-%m-%d") if isinstance(x.get("published"), str) else x.get("published", datetime.min),
            reverse=True
        )
        
        # Truncate to max results
        self.results["articles"] = self.results["articles"][:max_results]
        
        return {
            "target": target,
            "days_monitored": days,
            "total_articles": len(self.results["articles"]),
            "articles": self.results["articles"],
            "timestamp": time.time(),
        }
    
    async def _monitor_with_gnews(self, target: str, days: int, max_results: int) -> None:
        """
        Monitor news using GNews library.
        
        Args:
            target: Target domain or organization name
            days: Number of days to look back
            max_results: Maximum number of results to return
        """
        # GNews is synchronous, run in thread pool
        loop = asyncio.get_event_loop()
        
        def _run_gnews():
            # Initialize GNews with parameters
            gnews = GNews(
                language='en',
                country='US',
                period=days,
                max_results=max_results,
                exclude_websites=None
            )
            
            # Search for target
            return gnews.get_news(target)
        
        try:
            news_results = await loop.run_in_executor(None, _run_gnews)
            
            # Process results
            for article in news_results:
                # Format article data
                article_data = {
                    "title": article.get("title", "Untitled"),
                    "url": article.get("url", ""),
                    "published": article.get("published date", datetime.now().strftime("%Y-%m-%d")),
                    "publisher": article.get("publisher", {}).get("title", "Unknown"),
                    "snippet": article.get("description", "No description available"),
                }
                
                self.results["articles"].append(article_data)
            
            logger.info(f"Retrieved {len(self.results['articles'])} news articles with GNews")
        
        except Exception as e:
            logger.error(f"Error monitoring news with GNews: {str(e)}")
    
    @retry(max_retries=2, delay=1.0, backoff=2.0)
    async def _monitor_alternative(self, target: str, days: int, max_results: int) -> None:
        """
        Alternative news monitoring implementation using web requests.
        
        Args:
            target: Target domain or organization name
            days: Number of days to look back
            max_results: Maximum number of results to return
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Format dates for query
        start_str = start_date.strftime("%Y-%m-%d")
        end_str = end_date.strftime("%Y-%m-%d")
        
        # Encode query
        import urllib.parse
        encoded_target = urllib.parse.quote(target)
        
        try:
            # Try to use a public news API or RSS feed
            # For demonstration, we'll use a fictional endpoint
            # In a real implementation, this would use a real news API
            
            # Placeholder for demonstration
            logger.warning("Using alternative news monitoring method (placeholder)")
            
            # Generate some placeholder data
            publishers = [
                "Tech News Daily", "Business Insider", "Security Week",
                "The Daily Reporter", "Cyber Defense Magazine"
            ]
            
            titles = [
                f"{target} Announces New Security Measures",
                f"Industry Analysis: {target}'s Market Position",
                f"Experts Weigh In On {target}'s Latest Developments",
                f"Security Researchers Discover Vulnerability in {target}'s System",
                f"{target} Partners with Leading Cybersecurity Firm"
            ]
            
            # Generate random dates within range
            import random
            for i in range(min(5, max_results)):  # Limit to 5 placeholder articles
                days_ago = random.randint(0, days)
                pub_date = (end_date - timedelta(days=days_ago)).strftime("%Y-%m-%d")
                
                article = {
                    "title": titles[i % len(titles)],
                    "url": f"https://example.com/news/{encoded_target}/{i}",
                    "published": pub_date,
                    "publisher": publishers[i % len(publishers)],
                    "snippet": f"This is a placeholder article about {target}. In a real implementation, this would contain actual news content from a legitimate news source.",
                }
                
                self.results["articles"].append(article)
            
            logger.info(f"Added {len(self.results['articles'])} placeholder news articles")
        
        except Exception as e:
            logger.error(f"Error in alternative news monitoring: {str(e)}")
    
    async def search_google_news(self, query: str, days: int = 30) -> List[Dict[str, Any]]:
        """
        Search Google News directly (fallback method).
        
        Args:
            query: Search query
            days: Number of days to look back
            
        Returns:
            List of news article dictionaries
        """
        if not self.session:
            logger.error("Session not initialized. Use async with context.")
            return []
        
        # Note: Direct web scraping of Google News is against TOS
        # This is just a placeholder for how it might work in concept
        # In a real application, use proper API access
        
        logger.warning("Direct Google News scraping is not implemented - use GNews library")
        return []
    
    def extract_relevant_articles(self, articles: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
        """
        Filter articles to those most relevant to the target.
        
        Args:
            articles: List of articles
            target: Target domain or organization
            
        Returns:
            Filtered list of relevant articles
        """
        relevant = []
        
        for article in articles:
            # Check if target appears in title or snippet
            title = article.get("title", "").lower()
            snippet = article.get("snippet", "").lower()
            target_lower = target.lower()
            
            # Simple relevance scoring
            score = 0
            
            if target_lower in title:
                score += 5  # Higher score for title match
            
            if target_lower in snippet:
                score += 3  # Lower score for snippet match
            
            # Check for partial matches (for org names)
            for word in target_lower.split():
                if len(word) > 3:  # Only check substantial words
                    if word in title:
                        score += 2
                    if word in snippet:
                        score += 1
            
            # Add if score is high enough
            if score >= 3:
                article["relevance_score"] = score
                relevant.append(article)
        
        # Sort by relevance score
        relevant.sort(key=lambda x: x.get("relevance_score", 0), reverse=True)
        
        return relevant
