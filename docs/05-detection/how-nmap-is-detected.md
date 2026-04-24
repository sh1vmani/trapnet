# How Nmap Is Detected

Nmap is the most widely used network scanner in the world. It is used by security professionals for legitimate network auditing and by attackers for reconnaissance. trapnet detects Nmap with a confidence score of 0.8 using three independent signal types.

## Signal 1: Known probe strings

Nmap's service version detection (`-sV`) sends specific probe strings to each open port to fingerprint the service. These probes are defined in Nmap's `nmap-service-probes` file. Several of them are highly distinctive:

```python
nmap_probe_strings = [
    b"GET / HTTP/1.0",
    b"OPTIONS * HTTP/1.0",
    b"HELP\r\n",
    b"QUIT\r\n",
]
```

`GET / HTTP/1.0` is the Nmap HTTP probe. `OPTIONS * HTTP/1.0` is the Nmap HTTP options probe. `HELP\r\n` is sent to services that may respond to help commands (FTP, SMTP, POP3). `QUIT\r\n` is used to cleanly terminate connections with services that support it.

When any of these strings appear in the payload, the event is flagged as NMAP with the specific probe string recorded as an indicator.

## Signal 2: Multi-port sweep

Nmap's default scan mode hits multiple ports to determine which services are running. The detector tracks how many unique ports an IP has touched within the last 60 seconds:

```python
if unique_ports_60s > 7:
    nmap.append(f"{unique_ports_60s} unique ports hit in 60 seconds")
```

The threshold of 7 is deliberately higher than the generic scanner threshold (3) to separate Nmap from less systematic scanning. A typical Nmap default scan hits the top 1000 ports; a single trapnet instance only exposes 15 ports, so an IP that hits more than 7 of them within a minute is clearly performing a sweep.

## Signal 3: Zero-byte TCP payload

Nmap's TCP connect scan (`-sT`) and SYN scan (`-sS`) establish a TCP connection without sending any application data, purely to observe whether the port is open. These connections arrive at trapnet with an empty payload:

```python
if len(payload) == 0 and service not in ("udp",):
    nmap.append("zero byte payload on TCP service")
```

An empty payload on a TCP service is unusual in legitimate traffic. In conjunction with the other signals, it is a strong indicator of a port scan.

## Why the confidence is 0.8 and not higher

Nmap probe strings are distinctive, but they are also used by other tools that embed Nmap's probe library. The multi-port sweep signal can also be triggered by misconfigured monitoring tools. Zero-byte TCP probes occur in some legitimate health check systems. The 0.8 confidence reflects that the signals are strong but not exclusively attributable to Nmap.

## What the log record looks like

A detected Nmap scan produces an event like this:

```json
{
  "scanner_type": "NMAP",
  "confidence": 0.8,
  "indicators": [
    "Nmap probe string: b'GET / HTTP/1.0'",
    "12 unique ports hit in 60 seconds"
  ]
}
```

## Nmap timing modes

Nmap's timing templates (`-T0` through `-T5`) control how aggressively it probes. At `-T1` (sneaky), probes are spaced far apart to avoid detection. At `-T5` (insane), all probes are sent in parallel as fast as possible. trapnet's 60-second window may miss a very slow `-T1` scan, but will catch `-T3` (normal) and faster.

## Further reading

- [Understanding confidence scores](understanding-confidence-scores.md)
- [How attackers scan networks](../01-concepts/how-attackers-scan-networks.md)
- [Detector explained](../03-code-walkthrough/detector-explained.md)
