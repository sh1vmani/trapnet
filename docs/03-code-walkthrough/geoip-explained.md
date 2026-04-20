# geoip.py Explained

`trapnet/core/geoip.py` provides country and city lookups for attacker IP addresses using the ip-api.com free API.

## Module-level state

The module uses three module-level variables instead of a class:

```python
_cache: dict[str, dict]        # IP -> {country, city}
_last_request_time: float      # monotonic timestamp of last outbound request
_request_lock: asyncio.Lock    # created lazily on first lookup
```

These are module singletons. All callers share the same cache and rate limiter. A class-based design would work equally well, but the module approach avoids passing a GeoIP object through the entire call stack.

## Private IP handling

The `is_private()` function checks whether an IP falls in RFC1918 space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or loopback (127.0.0.0/8). Private IPs return `{"country": "Local", "city": "Local"}` immediately without making any external request.

This matters in two scenarios: testing trapnet locally, and deployments where the honeypot sits behind NAT and sees the attacker's internal IP after translation.

## Cache

The first lookup for any public IP makes an HTTP request and populates `_cache[ip]`. Subsequent lookups for the same IP return the cached result instantly, with no lock needed (the cache is written only when the lock is held, and dict reads are safe in Python's GIL even without locking).

The cache is in-memory and does not persist across restarts. A long-running deployment will accumulate cached entries over time. For a typical honeypot with diverse attacker IPs, this grows slowly and is not a memory concern.

## Rate limiting

ip-api.com's free tier allows 45 requests per minute. The module enforces a minimum of 1 second between requests (`_last_request_time` check), which yields at most 60 requests per minute and stays safely below the limit.

When a rate-limit wait is needed, the module uses `await asyncio.sleep(delay)`. This yields control back to the event loop during the wait, so other connections continue to be handled.

## Lock usage

The `_request_lock` serializes all outbound HTTP requests through a single coroutine at a time. It guards:

1. The double-checked cache read (to avoid redundant concurrent requests for the same IP).
2. The rate-limit sleep and request sequence.

The lock is created lazily inside `lookup()` because instantiating an `asyncio.Lock` at module import time -- before the event loop is running -- raises errors in Python 3.10+.

## Error handling

Any network error, timeout (2 seconds), or malformed response falls back to `{"country": "Unknown", "city": "Unknown"}`. GeoIP enrichment is best-effort. A lookup failure never causes a connection to go unlogged.

## Further reading

- [Data flow walkthrough](../02-architecture/data-flow-walkthrough.md)
- [Security implications of architecture](../02-architecture/security-implications-of-architecture.md)
