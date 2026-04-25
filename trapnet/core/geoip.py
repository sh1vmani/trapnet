# GeoIP lookups use ip-api.com free tier.
# Free tier is for non-commercial use, max 45 req/min.
# All lookups are cached for the session to minimize
# external requests. No attacker IPs are stored
# externally. Lookups are best-effort only.

from __future__ import annotations
import asyncio
import ipaddress
import time
import aiohttp

# Session-local cache: maps IP string to {country, city}
_cache: dict[str, dict] = {}

# Tracks the timestamp of the last outbound request for rate limiting
_last_request_time: float = 0.0

# Lock is created lazily inside lookup() to avoid instantiating asyncio
# primitives at import time, which raises DeprecationWarnings in Python 3.10+
# and errors in environments that enforce a running event loop at module load.
_request_lock: asyncio.Lock | None = None

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private(ip: str) -> bool:
    """Return True if ip is an RFC1918 or loopback address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


async def lookup(ip: str) -> dict:
    """Return {country, city} for the given IP address.

    Private and loopback addresses return {"country": "Local", "city": "Local"}
    without making an outbound request. Results are cached for the process
    lifetime. Falls back to {"country": "Unknown", "city": "Unknown"} on any
    network error or API failure.
    """
    global _request_lock
    if _request_lock is None:
        _request_lock = asyncio.Lock()

    # RFC1918 and loopback addresses never leave the host - no API call needed
    if is_private(ip):
        return {"country": "Local", "city": "Local"}

    if ip in _cache:
        return _cache[ip]

    async with _request_lock:
        # Re-check cache after acquiring lock in case another coroutine just populated it
        if ip in _cache:
            return _cache[ip]

        # Enforce max 1 request per second to stay well under the 45 req/min free-tier limit
        global _last_request_time
        elapsed = time.monotonic() - _last_request_time
        if elapsed < 1.0:
            await asyncio.sleep(1.0 - elapsed)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "country,city,status"},
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    data = await resp.json()

            _last_request_time = time.monotonic()

            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                }
            else:
                result = {"country": "Unknown", "city": "Unknown"}

        except Exception:
            # Any network error, timeout, or parse failure falls back silently
            result = {"country": "Unknown", "city": "Unknown"}

        _cache[ip] = result
        return result
