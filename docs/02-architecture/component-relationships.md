# Component Relationships

This document describes how each component in trapnet relates to and depends on the others.

## Dependency graph

```
config.yml
    |
    v
Config ---------> HoneypotEngine
                       |
              +--------+--------+
              |        |        |
           Logger  Detector   GeoIP
              |
           SQLite / JSON log files
              |
           Dashboard (Flask, reads SQLite)
```

## Config

`Config` is constructed first and passed into every other component. It holds no mutable state after construction. All other components treat it as read-only at runtime.

## HoneypotEngine

The engine owns the list of `asyncio.AbstractServer` objects. It is responsible for starting and stopping them. It holds references to `Logger`, `AttackDetector`, and `GeoIP`, and passes them down into each connection handler via `_EnrichedLogger`.

The engine does not know anything about specific protocols -- protocol logic lives entirely in `services.py`.

## Services

`services.py` contains one top-level async function per protocol (e.g., `handle_ssh`, `handle_ftp`). Each function receives a `StreamReader`, `StreamWriter`, an `_EnrichedLogger` instance, the `AttackDetector`, and the `Config`. It performs the protocol handshake, extracts credentials and payload, calls `detector.analyze()`, and writes a log entry.

Services are stateless. All per-connection state lives in local variables inside each handler call.

## AttackDetector

`AttackDetector` maintains a shared in-memory tracker of recent connection events, keyed by source IP. It is accessed concurrently by all active handlers and uses an `asyncio.Lock` to protect its internal state. It returns a classification dict without blocking other coroutines for more than a few microseconds.

## GeoIP

`GeoIP` wraps an HTTP client that calls ip-api.com. It uses an in-process cache to avoid redundant lookups. The engine wraps it in `_EnrichedLogger` so that the GeoIP lookup happens just before log writing, not at connection open time. This means a slow GeoIP response never delays the protocol handshake seen by the attacker.

## Logger

`Logger` writes connection records to two sinks simultaneously: a SQLite database and a newline-delimited JSON file. Both writes happen in a background thread (via `asyncio.to_thread`) to avoid blocking the event loop on disk I/O.

## Dashboard

The Flask app is entirely read-only. It queries the SQLite database that `Logger` writes to. It runs in a separate daemon thread and never touches any in-memory component. This isolation means a crash in the dashboard cannot affect the logging pipeline.

## Further reading

- [Data flow walkthrough](data-flow-walkthrough.md)
- [Async architecture explained](async-architecture-explained.md)
