# Logging and Forensics

The value of a honeypot is entirely in its logs. The events trapnet captures are the raw material for threat intelligence, incident response, and forensic analysis. Understanding what good logging looks like and how to preserve and analyze logs is essential for getting value from a honeypot deployment.

## What trapnet logs

Every connection produces a JSON record with the following fields:

```json
{
  "timestamp": "2026-04-23T14:32:01.123456+00:00",
  "src_ip": "203.0.113.42",
  "src_port": 51234,
  "dst_port": 22,
  "service": "ssh",
  "payload": "5353482d322e302d4f70656e5353485f372e392e...",
  "credentials": null,
  "scanner_type": "NMAP",
  "confidence": 0.8,
  "indicators": ["Nmap probe string: b'GET / HTTP/1.0'"],
  "country": "US",
  "asn": "AS15169",
  "org": "GOOGLE"
}
```

The `payload` field is hex-encoded raw bytes. This is intentional: raw bytes cannot introduce encoding issues and can be decoded later for analysis without loss. The `credentials` field is null for services that do not capture credentials and contains `username:password` for those that do.

## Log integrity

For forensic purposes, logs must be trustworthy. If an attacker can modify the log file, the forensic value is compromised.

**Append-only logging.** The log file should be opened in append mode. The process should not have permission to truncate or overwrite it. On Linux, the `chattr +a` attribute makes a file append-only even for root.

**Remote log shipping.** Sending logs to a remote syslog server or SIEM in real time means the logs survive even if the honeypot host is compromised. The remote system should be on a network the honeypot cannot reach (outbound-only log shipping via a one-way channel).

**Log rotation.** Logs should be rotated daily and compressed. Rotation should use `copytruncate` only if necessary; the preferred approach is to send a signal to trapnet to reopen the log file after rotation so the old file can be renamed intact.

## Forensic analysis of payloads

The hex-encoded payload contains the raw bytes the attacker sent. To decode it for analysis:

```python
payload_bytes = bytes.fromhex(event["payload"])
```

For text protocols (SSH, FTP, SMTP), you can decode as UTF-8 with error replacement:

```python
payload_text = payload_bytes.decode("utf-8", errors="replace")
```

For binary protocols (MySQL, PostgreSQL, MongoDB), use a hex dump tool or protocol-specific parser.

## Timestamp and timezone

trapnet logs timestamps in ISO 8601 format in UTC (`+00:00`). Using UTC consistently avoids ambiguity caused by daylight saving time transitions and timezone misconfigurations. When correlating trapnet logs with other systems, ensure those systems also log in UTC.

## Correlating events

A single attacker often appears as multiple events across different services. Correlation by `src_ip` across a time window reveals the full scope of an attacker's reconnaissance. An IP that appears in SSH, MySQL, and RDP events within a few minutes is running a multi-service sweep.

Correlation by `credentials` reveals when the same credential pair is being tested across multiple services or from multiple IPs (indicating the credential list is widely distributed).

## Retention policy

The appropriate retention period depends on your goals:

- **7 days:** Minimum for incident investigation
- **30 days:** Useful for tracking campaign evolution
- **1 year:** Sufficient for seasonal trends and long-term attacker tracking
- **Indefinite:** Required for legal proceedings; consult your legal jurisdiction

Logs containing personally identifiable information or credentials may be subject to data protection regulations. Review the legal and privacy implications for your jurisdiction before setting a long retention period.

## Further reading

- [IOC and threat intel](ioc-and-threat-intel.md)
- [Legal framework](legal-framework.md)
- [Logger explained](../03-code-walkthrough/logger-explained.md)
