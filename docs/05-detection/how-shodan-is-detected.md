# How Shodan Is Detected

Shodan is an internet-wide crawler that continuously scans all routable IP addresses, records service banners, and makes the data searchable. It indexes what services are running on what hosts, along with version strings, TLS certificate details, and other metadata. trapnet detects Shodan (and similar crawlers) with a confidence score of 0.7.

## What Shodan does

Shodan connects to every IP on every common port, reads the service banner, and disconnects. It does not attempt authentication or send exploit payloads. From a honeypot's perspective, a Shodan connection looks like:

1. TCP connection established.
2. If the protocol requires a client hello (HTTP), Shodan sends a minimal probe.
3. Shodan reads the server's first response.
4. Shodan disconnects.

This "banner grab and drop" pattern is the primary behavioral signal.

## Signal 1: Known crawler identifiers in HTTP User-Agent

Shodan, Censys, zgrab, and Masscan (in banner-grab mode) all identify themselves in the HTTP `User-Agent` header:

```python
for ua in (b"shodan", b"censys", b"zgrab", b"masscan"):
    if ua in payload_lower:
        shodan.append(f"known crawler identifier in request: {ua.decode()}")
```

This is the most reliable Shodan signal. Shodan's user agent strings include `Shodan` and variations of it. Censys uses `Censys`. zgrab2 (used by both Censys and custom research scanners) uses `zgrab`. When any of these appear in the payload, the detection is highly confident.

## Signal 2: Banner grab with no request body on web ports

Some crawlers connect to HTTP/HTTPS ports and send no data at all, waiting for the server to respond first. This is not valid HTTP behavior (HTTP requires the client to send a request), but some banner grabbers do it to see if the server emits anything unprompted.

```python
if service in ("http", "https"):
    if len(payload) == 0:
        shodan.append("banner grab with no request body on web port")
```

This signal only applies to web ports. An empty payload on a non-web port has other explanations (like Nmap's TCP SYN scan confirming port openness). On a web port, it is a strong indicator of a banner-grabbing crawler.

## Why detection is limited to web ports

Shodan scans all ports, but the distinctive "crawler identifier in payload" signal only appears in HTTP requests. For non-web ports (SSH, FTP, etc.), Shodan reads the server's banner without sending data, so there is no payload to inspect for its signature. On those ports, Shodan connections are indistinguishable from other zero-payload connections without out-of-band data (like BGP routing data or known Shodan IP ranges).

## Shodan vs Censys

Shodan and Censys are the two largest internet scanning services used by the security community. They both appear in the same detection category because their behavioral pattern (banner grab, no exploit attempt) is identical. The distinction matters for attribution but not for threat classification.

## Why 0.7 confidence

Shodan's user agent strings are reliable when present. But many custom security research tools also connect to ports, read banners, and disconnect without identifying themselves. The 0.7 confidence reflects the limitation: the crawler identity signals are strong, but the behavioral signals alone are not conclusive.

## Shodan in the context of a honeypot

Shodan discovering your honeypot is not necessarily bad. It means your honeypot is visible on the internet and responding correctly. Shodan's database is used by both attackers and defenders. If your honeypot shows up in Shodan search results as an Apache or MySQL server, it will attract more targeted scanner traffic, which is exactly what a honeypot is there to capture.

## Further reading

- [Understanding confidence scores](understanding-confidence-scores.md)
- [HTTP protocol](../04-protocols/http-protocol.md)
- [Detector explained](../03-code-walkthrough/detector-explained.md)
