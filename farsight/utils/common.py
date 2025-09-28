"""Common utility functions for FARSIGHT.

This module provides shared utilities including logging, rate limiting,
retry mechanisms, and other common functionality used across the framework.
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
import random
import asyncio

from farsight.config import get_config

# Create a custom colored logging handler
class ColoredConsoleHandler(logging.StreamHandler):
    """Custom handler for colored log output."""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',  # Cyan
        'INFO': '\033[32m',   # Green
        'WARNING': '\033[33m', # Yellow
        'ERROR': '\033[31m',   # Red
        'CRITICAL': '\033[41m', # White on Red background
        'RESET': '\033[0m'     # Reset color
    }
    
    def emit(self, record):
        # Get the log level name and corresponding color
        levelname = record.levelname
        color = self.COLORS.get(levelname, self.COLORS['RESET'])
        
        # Format the message with colors
        record.levelname = f"{color}{levelname}{self.COLORS['RESET']}"
        record.msg = f"{color}{record.msg}{self.COLORS['RESET']}"
        
        # Call the parent class emit
        super().emit(record)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[ColoredConsoleHandler()]
)
logger = logging.getLogger("farsight")


def set_log_level(level: str) -> None:
    """Set the log level."""
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")
    logger.setLevel(numeric_level)


T = TypeVar("T")


def retry(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
) -> Callable:
    """
    Retry decorator with exponential backoff.
    
    Args:
        max_retries: Maximum number of retries
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier e.g. 2 will double the delay each retry
        exceptions: Exceptions to catch and retry on
        
    Returns:
        Callable: Decorated function
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        async def wrapper_async(*args: Any, **kwargs: Any) -> T:
            local_max_retries = max_retries
            local_delay = delay
            last_exception = None
            
            while local_max_retries > 0:
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    logger.warning(
                        f"Retrying {func.__name__} in {local_delay:.2f}s due to {e.__class__.__name__}: {str(e)}"
                    )
                    last_exception = e
                    await asyncio.sleep(local_delay)
                    local_max_retries -= 1
                    local_delay *= backoff
                    
                    # Add jitter to avoid thundering herd
                    local_delay = local_delay * (0.9 + 0.2 * random.random())
            
            # If we get here, we've exhausted our retries
            logger.error(f"Function {func.__name__} failed after {max_retries} retries")
            if last_exception:
                raise last_exception
            raise Exception(f"Function {func.__name__} failed after {max_retries} retries")
            
        def wrapper_sync(*args: Any, **kwargs: Any) -> T:
            local_max_retries = max_retries
            local_delay = delay
            last_exception = None
            
            while local_max_retries > 0:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    logger.warning(
                        f"Retrying {func.__name__} in {local_delay:.2f}s due to {e.__class__.__name__}: {str(e)}"
                    )
                    last_exception = e
                    time.sleep(local_delay)
                    local_max_retries -= 1
                    local_delay *= backoff
                    
                    # Add jitter to avoid thundering herd
                    local_delay = local_delay * (0.9 + 0.2 * random.random())
            
            # If we get here, we've exhausted our retries
            logger.error(f"Function {func.__name__} failed after {max_retries} retries")
            if last_exception:
                raise last_exception
            raise Exception(f"Function {func.__name__} failed after {max_retries} retries")
        
        # Determine if the function is async or not and return the appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return wrapper_async
        return wrapper_sync
    
    return decorator


class RateLimiter:
    """Rate limiter for API calls."""
    
    def __init__(self, calls: int = 60, period: float = 60.0):
        """
        Initialize rate limiter.
        
        Args:
            calls: Number of calls allowed in the time period
            period: Time period in seconds
        """
        self.calls = calls
        self.period = period
        self.timestamps = []
    
    async def wait(self) -> None:
        """
        Wait until a call can be made without exceeding the rate limit.
        """
        now = time.time()
        
        # Remove timestamps outside the current period
        self.timestamps = [ts for ts in self.timestamps if now - ts <= self.period]
        
        # If we haven't hit the limit, we can proceed
        if len(self.timestamps) < self.calls:
            self.timestamps.append(now)
            return
        
        # We need to wait for the oldest timestamp to expire
        oldest = self.timestamps[0]
        wait_time = oldest + self.period - now
        
        if wait_time > 0:
            logger.debug(f"Rate limit hit. Waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
        
        # Add the current timestamp and remove the oldest
        self.timestamps.append(time.time())
        self.timestamps.pop(0)