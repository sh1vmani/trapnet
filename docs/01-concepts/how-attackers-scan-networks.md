# How Attackers Scan Networks

Before an attacker exploits anything, they need to know what is listening. Network scanning is the reconnaissance phase: finding live hosts, open ports, and service versions. Understanding how scanning works helps explain what trapnet captures and why.

## Port scanning

A TCP port scan sends a connection attempt to a port and observes the response:

- **SYN scan (half-open):** sends SYN, gets SYN-ACK (open) or RST (closed). Never completes the handshake. Fast and stealthy. Used by Nmap by default with root privileges.
- **Connect scan:** completes the full TCP handshake. Detectable in application logs. Used when raw sockets are unavailable.
- **UDP scan:** sends an empty UDP datagram. No response usually means open; ICMP port unreachable means closed. Slow and unreliable.

## Banner grabbing

Once a port is confirmed open, the scanner reads the server's greeting. SSH sends its version string, FTP sends a 220 banner, HTTP sends response headers. These banners identify the software and version, which the attacker maps to known CVEs.

## Tool signatures

Different tools leave distinct fingerprints:

**Nmap** sends specific probe strings on each port (`GET / HTTP/1.0`, `HELP\r\n`, `QUIT\r\n`) and often hits many ports from a single IP in a short window. It also performs version detection by sending protocol-specific payloads.

**Masscan** prioritizes speed over accuracy. It sends millions of SYN packets per second from a single machine, often with no payload at all. The connection rate from a single IP is the giveaway.

**Metasploit** modules send highly structured payloads. The EternalBlue SMB probe has a fixed byte pattern; the RDP scanner sends an X.224 connection request with a recognizable structure. These are essentially exploit fingerprints.

**Shodan and Censys** are internet-wide scanners run continuously by security research organizations. They identify themselves via HTTP User-Agent strings or other identifiers embedded in their requests. They are interested in banners, not exploitation.

**Credential stuffers** do not scan ports. They connect directly to a known service and replay username/password pairs from a leaked credential database. The tell is repeated authentication attempts on the same service, often with common passwords like `admin`, `root`, or `123456`.

## Scan timing and evasion

Sophisticated scanners slow their rate to avoid rate-limiting and IDS detection. They may distribute probes across multiple source IPs or introduce random delays. trapnet's behavioral detection uses a 60-second event window and tracks per-IP port diversity, so slow scans below the threshold register only as generic scanner activity.

## Why this matters for honeypots

A honeypot sits idle until something connects to it. Every incoming connection is a scan or attack event by definition. The challenge is not detecting that something happened, but identifying what kind of tool sent it and what the attacker was looking for.

## Further reading

- [Attack detection techniques](attack-detection-techniques.md)
- [How Nmap is detected](../05-detection/how-nmap-is-detected.md)
- [How Masscan is detected](../05-detection/how-masscan-is-detected.md)
