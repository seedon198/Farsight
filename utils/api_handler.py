"""API handler for making API requests with rate limiting and error handling."""

import aiohttp
import asyncio
import time
from typing import Any, Dict, List, Optional, Union
import json

from farsight.utils.common import logger, retry, RateLimiter
from farsight.config import get_api_key, get_api_endpoint, is_api_configured, get_config


class APIHandler:
    """Handler for API requests with rate limiting and error handling."""
    
    def __init__(self, provider: str):
        """
        Initialize API handler.
        
        Args:
            provider: API provider name
        """
        self.provider = provider
        self.api_key = get_api_key(provider)
        self.base_url = get_api_endpoint(provider)
        self.timeout = aiohttp.ClientTimeout(total=get_config("timeout", 30))
        
        # Set up rate limiter
        rate_limits = get_config("rate_limit", {})
        limit = rate_limits.get(provider, rate_limits.get("default", 60))
        self.rate_limiter = RateLimiter(calls=limit, period=60.0)
        
        # Check if API is configured
        if not self.api_key:
            logger.warning(f"{provider.capitalize()} API key not configured")
    
    async def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[aiohttp.BasicAuth] = None,
    ) -> Dict[str, Any]:
        """
        Make an API request.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            params: Query parameters
            data: Request body
            headers: HTTP headers
            auth: Basic auth credentials
            
        Returns:
            Response as a dictionary
        """
        # Check if API is configured
        if not self.api_key:
            raise ValueError(f"{self.provider.capitalize()} API key not configured")
        
        # Wait for rate limit
        await self.rate_limiter.wait()
        
        # Build URL
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Set up headers
        if headers is None:
            headers = {}
        
        # Add default headers including user agent
        default_headers = {
            "User-Agent": get_config("user_agent"),
            "Accept": "application/json",
        }
        headers = {**default_headers, **headers}
        
        # Add API key to headers or params based on provider
        if self.provider == "shodan":
            if params is None:
                params = {}
            params["key"] = self.api_key
        elif self.provider == "securitytrails":
            headers["APIKEY"] = self.api_key
        elif self.provider == "virustotal":
            headers["x-apikey"] = self.api_key
        elif self.provider == "intelx":
            headers["x-key"] = self.api_key
        elif self.provider == "leakpeek":
            headers["Authorization"] = f"Bearer {self.api_key}"
        # Add more providers as needed
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data,
                    headers=headers,
                    auth=auth,
                ) as response:
                    # Handle error responses
                    if response.status >= 400:
                        error_text = await response.text()
                        logger.error(
                            f"API error ({response.status}): {error_text}"
                        )
                        response.raise_for_status()
                    
                    # Parse response
                    if "application/json" in response.headers.get("Content-Type", ""):
                        return await response.json()
                    else:
                        return {"text": await response.text()}
        except aiohttp.ClientError as e:
            logger.error(f"API request error: {str(e)}")
            raise
    
    @retry(max_retries=3, delay=2.0, backoff=2.0)
    async def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Make a GET request.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: HTTP headers
            
        Returns:
            Response as a dictionary
        """
        return await self.request("GET", endpoint, params=params, headers=headers)
    
    @retry(max_retries=3, delay=2.0, backoff=2.0)
    async def post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Make a POST request.
        
        Args:
            endpoint: API endpoint
            data: Request body
            params: Query parameters
            headers: HTTP headers
            
        Returns:
            Response as a dictionary
        """
        return await self.request(
            "POST", endpoint, data=data, params=params, headers=headers
        )


class APIManager:
    """Manager for handling multiple API providers with failover."""
    
    def __init__(self):
        """Initialize API manager."""
        self.handlers: Dict[str, APIHandler] = {}
    
    def get_handler(self, provider: str) -> APIHandler:
        """
        Get API handler for a provider.