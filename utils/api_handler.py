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
        self.available_providers: Dict[str, bool] = {}
    
    def get_handler(self, provider: str) -> APIHandler:
        """
        Get API handler for a provider.
        
        Args:
            provider: API provider name
            
        Returns:
            APIHandler for the specified provider
        """
        # Check if handler exists
        if provider not in self.handlers:
            # Create new handler
            self.handlers[provider] = APIHandler(provider)
        
        return self.handlers[provider]
    
    async def check_availability(self, provider: str) -> bool:
        """
        Check if an API provider is available.
        
        Args:
            provider: API provider name
            
        Returns:
            True if provider is available, False otherwise
        """
        # Check if already checked
        if provider in self.available_providers:
            return self.available_providers[provider]
        
        try:
            # Get handler for provider
            handler = self.get_handler(provider)
            
            # Try a simple API request to check availability
            if provider == "shodan":
                await handler.get("api-info")
            elif provider == "censys":
                await handler.get("v2/account")
            elif provider == "securitytrails":
                await handler.get("v1/ping")
            elif provider == "virustotal":
                await handler.get("users/current")
            elif provider == "intelx":
                await handler.get("authenticate/info")
            elif provider == "leakpeek":
                await handler.get("user")
            # Add more providers as needed
            
            # If no exception was raised, API is available
            self.available_providers[provider] = True
            logger.info(f"{provider.capitalize()} API is available")
            return True
        except Exception as e:
            self.available_providers[provider] = False
            logger.warning(f"{provider.capitalize()} API is not available: {str(e)}")
            return False
    
    async def get_available_handler(self, preferred_providers: List[str]) -> Optional[APIHandler]:
        """
        Get first available handler from a list of preferred providers.
        
        Args:
            preferred_providers: List of preferred API providers in order of preference
            
        Returns:
            First available APIHandler or None if none available
        """
        for provider in preferred_providers:
            if await self.check_availability(provider):
                return self.get_handler(provider)
        
        return None
    
    async def execute_with_failover(self, 
                                   providers: List[str], 
                                   method_name: str, 
                                   *args, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Execute a method with failover support across multiple providers.
        
        Args:
            providers: List of API providers to try in order
            method_name: Method to call on each handler
            *args: Arguments to pass to the method
            **kwargs: Keyword arguments to pass to the method
            
        Returns:
            Response from first successful API call or None if all fail
        """
        for provider in providers:
            try:
                if not await self.check_availability(provider):
                    continue
                
                handler = self.get_handler(provider)
                method = getattr(handler, method_name)
                return await method(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Failed to execute {method_name} with {provider}: {str(e)}")
                continue
        
        logger.error(f"All providers failed to execute {method_name}")
        return None