"""Local disk cache for IntelX searches.

IntelX bills a search credit each time `POST /<bucket>/search` starts a new
search, but `GET /<bucket>/search/result?id=...` (fetching results for an
existing search ID) is free. This module lets callers hash a search's
endpoint+params to a cache key so that:

- An identical query made again within the TTL is served entirely from
  disk, with no API call at all.
- An identical query made again after the TTL (or before results ever
  arrived) reuses the stored search ID and only calls the free result
  endpoint, instead of paying for a new search.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from farsight import config
from farsight.utils.common import logger


def _cache_key(endpoint: str, params: Dict[str, Any]) -> str:
    """Hash a search endpoint + its params into a stable cache key."""
    payload = json.dumps({"endpoint": endpoint, "params": params}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(endpoint: str, params: Dict[str, Any]) -> Path:
    # Read config.CACHE_DIR at call time (not import time) so tests can
    # redirect it to an isolated temp directory.
    return config.CACHE_DIR / f"{_cache_key(endpoint, params)}.json"


def load(endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Load the cache entry for a search, if one exists on disk."""
    path = _cache_path(endpoint, params)
    if not path.exists():
        return None

    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Failed to read IntelX cache entry {path}: {e}")
        return None


def save(
    endpoint: str,
    params: Dict[str, Any],
    search_id: str,
    records: Optional[Any] = None,
) -> None:
    """Persist a search ID (and optionally its results) for reuse."""
    entry = {
        "search_id": search_id,
        "records": records,
        "cached_at": time.time(),
    }

    path = _cache_path(endpoint, params)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry))
    except OSError as e:
        logger.warning(f"Failed to write IntelX cache entry {path}: {e}")


def is_fresh(entry: Dict[str, Any]) -> bool:
    """Whether a cached entry's results are still within the TTL."""
    ttl = config.get_config("intelx_cache_ttl", 21600)
    return (time.time() - entry.get("cached_at", 0)) < ttl
