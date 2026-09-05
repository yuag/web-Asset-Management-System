"""Tiny thread-safe TTL cache with explicit invalidation.

Usage:
    value = cache.get("stats:dashboard", loader_fn, ttl=15)
    cache.invalidate("stats:dashboard")
    cache.invalidate_prefix("stats:")
"""
import threading
import time

_cache = {}
_lock = threading.Lock()
# Upper bound on entries. Search-result keys are cached per exact
# filter/pagination combination; without a cap, a scan over many pages or
# many hot queries would grow the dict forever.
MAX_ENTRIES = 512


def _prune():
    """Drop expired entries, then evict the soonest-expiring ones beyond the cap.
    Caller must hold `_lock`."""
    now = time.time()
    expired = [k for k, v in _cache.items() if v[1] <= now]
    for k in expired:
        _cache.pop(k, None)
    if len(_cache) > MAX_ENTRIES:
        overflow = sorted(_cache.items(), key=lambda kv: kv[1][1])[: len(_cache) - MAX_ENTRIES]
        for k, _ in overflow:
            _cache.pop(k, None)


def get(key, loader, ttl=60):
    """Return cached value for `key` or compute it via `loader()` and cache it."""
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and hit[1] > now:
            return hit[0]
    value = loader()
    with _lock:
        _cache[key] = (value, now + ttl)
        _prune()
    return value


def set(key, value, ttl=60):
    with _lock:
        _cache[key] = (value, time.time() + ttl)
        _prune()


def invalidate(*keys):
    with _lock:
        for k in keys:
            _cache.pop(k, None)


def invalidate_prefix(prefix):
    with _lock:
        stale = [k for k in _cache if k.startswith(prefix)]
        for k in stale:
            _cache.pop(k, None)


def clear():
    with _lock:
        _cache.clear()