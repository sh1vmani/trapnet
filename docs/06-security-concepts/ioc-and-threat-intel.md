# IOC and Threat Intelligence

An IOC (Indicator of Compromise) is a piece of forensic data that suggests a host or network may have been involved in a security incident. Threat intelligence is the broader practice of collecting, analyzing, and sharing information about adversary behavior. trapnet generates raw data that can be processed into both.

## Types of IOCs

**Network IOCs:**
- IP addresses that have been observed attacking systems
- Domains used for malware command-and-control
- URLs used for payload hosting
- Port/protocol combinations associated with specific attack tools

**Host IOCs:**
- File hashes of known malware
- Registry keys created by malware
- Process names used by attack tools

trapnet generates network IOCs. Every source IP in the log is a potential IOC. IPs that trigger scanner detection (especially METASPLOIT or MASSCAN) are stronger IOCs than IPs with generic or null detections.

## IOC quality

Not all IOCs are equally useful. Quality dimensions:

**Specificity.** An IP that sent a Metasploit EternalBlue probe is a specific IOC tied to a particular attack tool. An IP that connected to port 22 with an empty payload is not specific.

**Recency.** IOCs decay in value over time. IP addresses are reassigned, VPNs and proxies cycle their addresses, and botnets migrate infrastructure. An IOC from 6 months ago has limited operational value without corroboration.

**Context.** An IOC with context (which tool, which vulnerability, which campaign) is more actionable than a bare IP address. The `scanner_type`, `indicators`, and `service` fields in trapnet logs provide this context.

## Generating IOCs from trapnet logs

A minimal IOC extraction from trapnet's JSONL log:

```python
import json
from datetime import datetime, timezone, timedelta

cutoff = datetime.now(timezone.utc) - timedelta(days=7)
iocs = []

with open("trapnet.log") as f:
    for line in f:
        event = json.loads(line)
        ts = datetime.fromisoformat(event["timestamp"])
        if ts < cutoff:
            continue
        if event.get("scanner_type") in ("METASPLOIT", "MASSCAN", "NMAP"):
            iocs.append({
                "ip": event["src_ip"],
                "type": event["scanner_type"],
                "port": event["dst_port"],
                "service": event["service"],
                "seen": event["timestamp"],
            })
```

## Sharing threat intelligence

**Formats.** STIX (Structured Threat Information Expression) and MISP (Malware Information Sharing Platform) are the standard formats for sharing threat intelligence between organizations. A trapnet log can be converted into STIX Indicators or MISP events.

**Sharing platforms.** CIRCL (the Computer Incident Response Center Luxembourg) operates a public MISP instance. ISACs (Information Sharing and Analysis Centers) operate sector-specific sharing for finance, energy, healthcare, and other industries.

**Operational sharing.** If you observe an active attack campaign, sharing IOCs with your ISP, your cloud provider's security team, or your national CERT can result in faster blocking or takedown of the attacker's infrastructure.

## The TLP marking system

TLP (Traffic Light Protocol) is used to indicate how widely shared information can be redistributed:

| Color | Meaning |
|-------|---------|
| TLP:RED | Recipient only, not for redistribution |
| TLP:AMBER | Limited redistribution within your organization and trusted partners |
| TLP:GREEN | Community sharing within a defined community |
| TLP:CLEAR | Unrestricted, can be shared publicly |

Trapnet IOCs that include attacker credentials should be marked TLP:AMBER or TLP:RED until the credentials are revoked or the campaign is over. Bare IP/scanner-type data can usually be TLP:GREEN or TLP:CLEAR.

## Further reading

- [Threat intelligence basics](../01-concepts/threat-intelligence-basics.md)
- [Logging and forensics](logging-and-forensics.md)
- [Responsible disclosure](responsible-disclosure.md)
