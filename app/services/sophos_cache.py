"""Server-side TTL cache for Sophos API responses."""

import threading
import time

_cache = {}
_lock = threading.Lock()
DEFAULT_TTL = 300  # 5 minutes


def cache_get(key):
    """Return cached value if not expired, else None."""
    with _lock:
        entry = _cache.get(key)
        if entry and time.time() < entry["expires"]:
            return entry["value"]
        if entry:
            del _cache[key]
        return None


def cache_set(key, value, ttl=DEFAULT_TTL):
    """Store value in cache with TTL."""
    with _lock:
        _cache[key] = {"value": value, "expires": time.time() + ttl}


def cache_invalidate(*prefixes):
    """Invalidate all cache keys matching any of the given prefixes."""
    with _lock:
        keys_to_delete = [
            k for k in _cache
            if any(k.startswith(p) for p in prefixes)
        ]
        for k in keys_to_delete:
            del _cache[k]


def cache_clear():
    """Clear all cached entries."""
    with _lock:
        _cache.clear()
