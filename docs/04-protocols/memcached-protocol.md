# Memcached Protocol

Memcached runs on TCP port 11211 (and also UDP port 11211). It is a distributed memory caching system used to reduce database load in web applications. Memcached has no authentication in its default configuration. Exposed Memcached servers have been exploited for data exfiltration and, via UDP, for one of the largest DDoS reflection attacks ever recorded.

## How Memcached communication works

Memcached uses a plain-text protocol for most operations. Commands are ASCII lines terminated with `\r\n`:

```
stats\r\n
get mykey\r\n
set mykey 0 3600 5\r\nvalue\r\n
delete mykey\r\n
flush_all\r\n
```

Responses are also plain text. The `stats` command returns a list of server statistics. The `get` command returns the stored value or `END\r\n` if not found.

## What trapnet does

trapnet reads up to 1024 bytes and branches on the command:

```python
MEMCACHED_STATS = (
    b"STAT pid 1\r\n"
    b"STAT uptime 3600\r\n"
    b"STAT version 1.6.12\r\n"
    b"END\r\n"
)
MEMCACHED_ERROR = b"ERROR\r\n"
```

If the payload starts with `stats` (case-insensitive), trapnet returns a minimal stats response. Otherwise it returns `ERROR\r\n`. The `STAT version 1.6.12` line identifies the emulated software version. The `stats` response is what most scanners use to confirm a Memcached server is present and to determine its version.

## The 2018 Memcached DDoS amplification attacks

In February 2018, attackers used exposed Memcached servers as amplification vectors. The attack exploited UDP port 11211:

1. Attacker sends a small UDP request (a few hundred bytes) to a Memcached server with a spoofed source IP (the victim's IP).
2. The Memcached server sends a large response (potentially megabytes from `get` of a large value) to the victim's IP.

Amplification factors of 50,000x were observed. The largest attacks reached over 1 Tbps. This made Memcached the highest-amplification DDoS vector ever discovered, surpassing DNS and NTP. Most cloud providers now block UDP port 11211 at the network edge.

## What the stats response reveals

A real `stats` response includes hundreds of fields covering memory usage, connection counts, hit/miss ratios, and uptime. The minimal response trapnet returns (pid, uptime, version) is enough to satisfy a scanner. A more complete response would reveal operational data that is not useful for a honeypot.

## Common attacker behaviors

**Stats probing.** The first command from almost every scanner is `stats\r\n`. The response confirms the server is Memcached, reveals the version, and in a real server would show memory usage (indicating how much data is cached).

**Data extraction.** After confirming access, attackers iterate through cache keys using `stats items`, `stats cachedump`, and `get` commands to extract cached session tokens, authentication data, or application data.

**flush_all.** Some automated attack tools run `flush_all\r\n` to clear all cached data, causing performance degradation in the application relying on the cache.

## Further reading

- [Redis protocol](redis-protocol.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
- [Network isolation best practices](../06-security-concepts/network-isolation-best-practices.md)
