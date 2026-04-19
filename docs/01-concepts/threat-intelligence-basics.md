# Threat Intelligence Basics

Threat intelligence is structured information about adversary behavior that helps defenders make better decisions. Honeypot logs are a raw source of threat intelligence. This document explains the concepts and how trapnet data fits into them.

## Indicators of Compromise (IOCs)

An IOC is a piece of observable data that suggests a system or network has been attacked or is under investigation. Common IOC types:

| IOC type | Example from trapnet |
|---|---|
| IP address | Source IP that connected to the honeypot |
| Port | Destination port that was probed |
| User-Agent string | `shodan`, `zgrab` in HTTP headers |
| Credential pair | `admin:password` captured on FTP |
| Payload hash | MD5 of an exploit payload |
| Tool signature | EternalBlue SMB probe bytes |

trapnet logs the raw materials for IP, port, and payload IOCs. You extract the structured indicators from the log data.

## Tactical vs. strategic intelligence

**Tactical intelligence** is actionable in the short term: an IP that is actively scanning your honeypot right now. You might block it at your firewall. Its shelf life is hours to days.

**Strategic intelligence** is longer-lived: which vulnerability classes are being mass-exploited this month, which tools are most common, whether credential stuffing on your industry's common admin panels is increasing. This comes from aggregating honeypot data over weeks and months.

trapnet supports both. Individual log records are tactical. Aggregate statistics from the `/api/stats` dashboard endpoint and the SQLite database are strategic.

## Enrichment

Raw IOCs become more useful with context. trapnet adds:

- **GeoIP** - country and city for each source IP. Useful for spotting geographic concentrations of attack activity.
- **Scanner type** - knowing an IP is running Masscan vs. a targeted Metasploit exploit changes the response. Masscan is automated noise; Metasploit suggests a human operator.
- **Confidence score** - how certain the detection is. A 0.9 confidence Metasploit detection warrants more attention than a 0.5 confidence generic scanner flag.

## Sharing and feeds

IOCs collected from honeypots are often shared in threat intelligence feeds (STIX/TAXII, MISP, abuse.ch). trapnet does not include a sharing mechanism, but the JSON log format is easy to parse and ingest into external platforms.

Before sharing IOCs, consider that source IPs in honeypot logs may include:

- Misconfigured legitimate services
- Tor exit nodes and VPN endpoints used by security researchers
- Compromised hosts that are themselves victims

Sharing with context (scanner type, confidence, payload) is more responsible than sharing raw IP lists.

## Further reading

- [IOC and threat intel](../06-security-concepts/ioc-and-threat-intel.md)
- [Logging and forensics](../06-security-concepts/logging-and-forensics.md)
- [Understanding confidence scores](../05-detection/understanding-confidence-scores.md)
