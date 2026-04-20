# Data Flow Walkthrough

This document traces the path of a single attacker connection from the first TCP packet to the final log entry.

## 1. TCP connection arrives

An attacker connects to port 22 (SSH). The OS accepts the TCP handshake and queues the connection. The asyncio event loop picks it up and calls the handler registered by `HoneypotEngine` for that port.

## 2. Handler is dispatched

`HoneypotEngine._make_handler()` wraps the protocol-specific function in a closure that:

- extracts the source IP from the socket
- constructs an `_EnrichedLogger` that pairs the logger and GeoIP objects with that IP

The closure calls `handle_ssh(reader, writer, enriched_logger, detector, config)`.

## 3. Protocol handshake

`handle_ssh()` sends the SSH banner immediately:

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n
```

It then reads up to 256 bytes from the attacker. This is the attacker's version string or first probe payload.

## 4. Detection

`handle_ssh()` calls `detector.analyze(src_ip, dst_port, payload, "ssh")`. The detector:

1. Cleans stale events older than 5 minutes from its tracker.
2. Records this event (timestamp, port, service) under the source IP.
3. Evaluates the payload and recent event history against all scanner signatures.
4. Returns a dict: `{"scanner_type": "NMAP", "confidence": 0.8, "indicators": [...]}`.

## 5. Log entry is assembled

The handler builds a connection record dict:

```python
{
    "timestamp": "2026-04-20T10:23:14+00:00",
    "src_ip": "45.33.32.156",
    "dst_port": 22,
    "service": "ssh",
    "payload_hex": "5353482d322e302d...",
    "scanner_type": "NMAP",
    "confidence": 0.8,
    "indicators": ["Nmap probe string: b'HELP\\r\\n'"],
    "username": null,
    "password": null,
}
```

## 6. GeoIP enrichment

The handler calls `enriched_logger.log_connection(record)`. Inside, `_EnrichedLogger` calls `geoip.lookup(src_ip)`, which either returns a cached result or makes an HTTP request to ip-api.com. The country and city fields are added to the record dict.

## 7. Dual log write

`Logger.log_connection(record)` runs two writes concurrently:

- `asyncio.to_thread(self._write_sqlite, record)` -- inserts a row into the SQLite `connections` table
- `asyncio.to_thread(self._write_json, record)` -- appends a JSON line to `logs/trapnet.json`

Both are awaited together with `asyncio.gather()`. The event loop is free to handle other connections while the disk I/O is in flight.

## 8. Connection closed

After the handler returns, `asyncio` closes the socket. The attacker's connection is terminated.

## 9. Dashboard reads the record

The next time a browser loads the dashboard, Flask queries SQLite for the 500 most recent connections and renders them. The dashboard sees the record that was written in step 7.

## Timing notes

Steps 1 through 6 typically complete in under 1 millisecond. Step 6 (GeoIP) can take 20-200 ms if the cache is cold -- but because it is `await`ed, the event loop handles other connections during this wait. The attacker's connection is kept open until GeoIP resolves, which is intentional: it prevents the log entry from being written with missing geo data.

## Further reading

- [Component relationships](component-relationships.md)
- [Async architecture explained](async-architecture-explained.md)
