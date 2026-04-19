# Attack Detection Techniques

trapnet uses three complementary techniques to classify incoming connections: payload signature matching, behavioral analysis, and protocol heuristics. This document explains each technique and how they combine.

## 1. Payload signature matching

The simplest form of detection looks for known byte sequences in the raw payload. Examples:

- The string `msfconsole` or `metasploit` in any payload is a direct Metasploit indicator.
- An SMB probe beginning with `\x00\x00\x00\x2f\xff\x53\x4d\x42` matches the EternalBlue packet structure.
- HTTP requests containing `shodan`, `censys`, or `zgrab` in the User-Agent are crawler signatures.
- Known Nmap probe strings (`GET / HTTP/1.0`, `OPTIONS * HTTP/1.0`, `HELP\r\n`, `QUIT\r\n`) appear verbatim in its service version probes.

Signature matching is fast and produces high-confidence results when a match is found. Its limitation is that it only catches known tools. A custom scanner with no known signatures will not match.

## 2. Behavioral analysis

Behavioral detection tracks what a single source IP does over time, not just what it sends in one packet.

**Port sweep detection:** if a source IP touches more than 7 distinct ports within 60 seconds, it is behaving like a port scanner regardless of what it sends. trapnet flags this as likely Nmap (>7 ports) or a generic scanner (>3 ports).

**Rate detection:** more than 20 connections from one IP within 10 seconds indicates Masscan-style high-rate scanning. The connection rate is the primary Masscan signature because Masscan payloads are often empty.

**Credential stuffing detection:** more than 3 authentication attempts on the same service within 30 seconds, especially combined with common password strings in the payload, indicates a credential stuffing campaign.

Behavioral detection catches novel tools that share scanning patterns with known ones, even when their payloads do not match any signature.

## 3. Protocol heuristics

Some detections rely on protocol-level observations rather than specific content:

- A zero-byte payload on a TCP service (the connection opened and immediately closed) is characteristic of an Nmap SYN scan or a connect scan where no data was sent. Combined with other signals, it raises the Nmap confidence score.
- A zero-byte payload on an HTTP or HTTPS port, combined with no recognizable User-Agent, is consistent with a banner-grab-and-drop operation typical of Shodan.

## Confidence scores

Each category has a fixed confidence score reflecting how reliable its detection signals are:

| Category | Score | Rationale |
|---|---|---|
| METASPLOIT | 0.90 | Payload signatures are highly specific |
| MASSCAN | 0.85 | Connection rate is a very strong signal |
| NMAP | 0.80 | Probe strings and port sweep pattern |
| SHODAN | 0.70 | Crawler identifiers, but web-only |
| CREDENTIAL_STUFFER | 0.75 | Auth rate plus known password strings |
| GENERIC_SCANNER | 0.50 | Port sweep only, no specific tool ID |

When multiple categories match, trapnet reports the highest-confidence one.

## Further reading

- [Understanding confidence scores](../05-detection/understanding-confidence-scores.md)
- [How Nmap is detected](../05-detection/how-nmap-is-detected.md)
- [How Metasploit is detected](../05-detection/how-metasploit-is-detected.md)
