"""Configuration module for FARSIGHT.

This module handles all configuration settings, API key management,
and environment variable processing for the FARSIGHT framework.
"""

import os
from pathlib import Path
from typing import Dict, Optional, Any

# Base directories - dynamically determined at runtime
PROJECT_ROOT = Path(__file__).parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

# Ensure reports directory exists for output files
REPORTS_DIR.mkdir(exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    # General settings
    "log_level": "INFO",
    "timeout": 30,  # Default timeout for HTTP requests in seconds
    "user_agent": "FARSIGHT/0.1.0 (+https://github.com/seedon198/farsight)",
    "max_concurrent_requests": 10,
    
    # Module-specific settings
    "dns_wordlist": "default",
    "dns_resolver": "1.1.1.1",
    "port_scan_timeout": 2,
    "default_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "typosquat_threshold": 80,  # Similarity threshold for typosquat detection
    "news_results_limit": 10,
    
    # Rate limiting
    "rate_limit": {
        "default": 60,  # requests per minute
        "shodan": 60,
        "censys": 120,
        "virustotal": 4,
    },
}

# API settings - first try env vars, then fallback to None
API_KEYS = {
    "shodan": os.environ.get("FARSIGHT_SHODAN_API_KEY"),
    "censys": os.environ.get("FARSIGHT_CENSYS_API_KEY"),
    "securitytrails": os.environ.get("FARSIGHT_SECURITYTRAILS_API_KEY"),
    "virustotal": os.environ.get("FARSIGHT_VIRUSTOTAL_API_KEY"),
    "intelx": os.environ.get("FARSIGHT_INTELX_API_KEY"),
    "leakpeek": os.environ.get("FARSIGHT_LEAKPEEK_API_KEY"),
}

# User-overridable config from env vars
USER_CONFIG = {}

# API endpoints
API_ENDPOINTS = {
    "shodan": "https://api.shodan.io",
    "censys": "https://search.censys.io/api",
    "securitytrails": "https://api.securitytrails.com",
    "virustotal": "https://www.virustotal.com/api/v3",
    "intelx": "https://2.intelx.io",
    "leakpeek": "https://api.leakpeek.com",
}


def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value by key."""
    # Look in user config first, then default config, then return provided default
    return USER_CONFIG.get(key, DEFAULT_CONFIG.get(key, default))


def get_api_key(provider: str) -> Optional[str]:
    """Get API key for a specific provider."""
    return API_KEYS.get(provider)


def get_api_endpoint(provider: str) -> Optional[str]:
    """Get API endpoint for a specific provider."""
    return API_ENDPOINTS.get(provider)


def is_api_configured(provider: str) -> bool:
    """Check if API key is configured for a provider."""
    return get_api_key(provider) is not None


def get_available_apis() -> Dict[str, bool]:
    """Get a mapping of all APIs and whether they're configured."""
    return {provider: is_api_configured(provider) for provider in API_KEYS.keys()}