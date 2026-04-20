# detector.py Explained

`trapnet/core/detector.py` contains `AttackDetector`, the component that fingerprints the tool behind each connection.

## What it classifies

The detector identifies six scanner categories:

| Category | Confidence | Key signal |
|---|---|---|
| METASPLOIT | 0.90 | Payload strings or protocol-specific exploit signatures |
| MASSCAN | 0.85 | Extremely high connection rate (>20 in 10 seconds) |
| NMAP | 0.80 | Known probe strings or multi-port sweep (>7 ports/60s) |
| SHODAN | 0.70 | Crawler User-Agent strings on HTTP/HTTPS |
| CREDENTIAL_STUFFER | 0.75 | Rapid auth attempts on SSH/FTP/Telnet/POP3/SMTP |
| GENERIC_SCANNER | 0.50 | Any IP hitting more than 3 ports in 60 seconds |

## Per-IP event tracking

`_tracker` is a dict mapping each source IP to a list of `(timestamp, port, service)` tuples. Every call to `analyze()` appends one tuple and takes a snapshot. The detection logic operates on the snapshot, not the live list, to minimize time spent holding the lock.

Entries older than 5 minutes are pruned at the start of each `analyze()` call. This bounds memory use: an IP that stops connecting eventually disappears from the tracker.

## The asyncio.Lock

The lock protects the `_tracker` dict against concurrent reads and writes from simultaneous handler coroutines. Because asyncio is single-threaded, the lock only prevents two coroutines from interleaving within an `await` sequence, not true parallel access. It is created lazily to avoid the `DeprecationWarning` that asyncio raises when primitives are instantiated before a running event loop.

## Detection logic

The detector evaluates all six categories for every connection and collects any that match into a `candidates` dict. When multiple categories match (e.g., Nmap and Generic both trigger on a port sweep), the one with the highest confidence wins.

This means a generic port sweep is classified as NMAP, not GENERIC_SCANNER, because NMAP has a higher confidence and also triggers on that signal.

## Confidence scores

Confidence is a float in 0.0-1.0. It reflects how certain the classifier is, not the severity of the attack. A 0.9 confidence for METASPLOIT means the payload contained a Metasploit-specific signature; a 0.5 for GENERIC_SCANNER means only the port sweep pattern was seen.

The threshold for alerting is set in `config.yml` under `detection.alert_threshold`. This is a count of connections from the same IP, not a confidence threshold -- it is used upstream by any alerting integration, not by the detector itself.

## Return value

```python
{
    "scanner_type": "NMAP",       # or None if no match
    "confidence": 0.8,
    "indicators": [
        "Nmap probe string: b'GET / HTTP/1.0'",
        "12 unique ports hit in 60 seconds",
    ]
}
```

## Further reading

- [How nmap is detected](../05-detection/how-nmap-is-detected.md)
- [How Metasploit is detected](../05-detection/how-metasploit-is-detected.md)
- [Understanding confidence scores](../05-detection/understanding-confidence-scores.md)
