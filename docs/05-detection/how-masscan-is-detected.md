# How Masscan Is Detected

Masscan is an extremely fast TCP port scanner capable of scanning the entire internet in under 6 minutes. It achieves this speed by sending packets asynchronously without maintaining TCP state, using a custom userland TCP/IP stack. trapnet detects Masscan with a confidence score of 0.85.

## What makes Masscan distinctive

Masscan's speed is its signature. It can send millions of packets per second. When a Masscan scan hits your IP, you see many connections from the same source IP in a very short time window. The payloads are typically empty because Masscan is usually configured to only confirm port openness, not to read service banners.

## Signal 1: High connection rate

```python
if len(events_last_10s) > 20:
    masscan.append(f"{len(events_last_10s)} connections from same IP in 10 seconds")
```

More than 20 connections from the same IP within 10 seconds is a rate that legitimate traffic almost never reaches. Even aggressive monitoring tools do not hit a single host this frequently. This is the primary Masscan indicator.

## Signal 2: Zero-byte payload at elevated rate

```python
if len(payload) == 0 and len(events_last_10s) > 5:
    masscan.append("zero byte payload at high connection rate")
```

When Masscan is configured in its default mode, it sends no application data. It just completes the TCP three-way handshake to confirm port openness. An empty payload at a high connection rate strongly suggests Masscan. This threshold is lower (5 connections) than the first signal because the combination of empty payload and any elevated rate is already unusual.

## Why 0.85 confidence

The high connection rate is the clearest scanner signal trapnet tracks, second only to specific Metasploit payload signatures. However, there is a scenario where a large distributed scanner could present at moderate per-IP rates while still being Masscan, and there are rare cases where a misconfigured load balancer or monitoring system from a single IP could produce high connection rates. The 0.85 confidence acknowledges this.

## Masscan vs Zmap

Zmap is a similar internet-wide scanner. It also sends packets at very high rates and produces empty payloads. The detection signals for Masscan and Zmap are identical from trapnet's perspective. The `MASSCAN` label in the event should be interpreted as "high-rate stateless scanner" rather than specifically the Masscan binary.

## Masscan's default behavior on known ports

On ports where Masscan is configured with banner grabbing, it will send a small probe string to read the service banner. On HTTP ports, it sends `GET / HTTP/1.0\r\n\r\n`. This overlaps with an Nmap probe string. When both Masscan rate indicators and Nmap probe strings are present, the detector selects the highest-confidence match. Masscan (0.85) wins over Nmap (0.8), so the event will be labeled MASSCAN.

## Practical implication

A Masscan detection means the source IP is running an automated large-scale internet scan, not targeting your system specifically. The IP is likely scanning your entire /24 or the entire internet. This is useful threat intelligence because it means you can expect to see the same IP hitting your real infrastructure within the same scan window.

## Further reading

- [Understanding confidence scores](understanding-confidence-scores.md)
- [How Nmap is detected](how-nmap-is-detected.md)
- [Detector explained](../03-code-walkthrough/detector-explained.md)
