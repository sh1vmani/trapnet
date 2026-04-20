# System Overview

trapnet is structured as a single Python process that runs multiple concurrent network listeners, a web dashboard, and a background log writer, all sharing one event loop.

## Top-level layout

```
trapnet/
  config.py          - loads and validates config.yml at startup
  __main__.py        - entry point: wires up all components and starts the engine
  core/
    engine.py        - manages asyncio servers for each enabled service
    services.py      - per-protocol handler functions
    detector.py      - attack-tool fingerprinting logic
    geoip.py         - async GeoIP enrichment via ip-api.com
    logger.py        - dual-sink log writer (SQLite + JSON)
  dashboard/
    app.py           - Flask web app served via a background thread
  integrations/
    snort.py         - optional Snort alert file reader
```

## Startup sequence

1. `__main__.py` calls `Config.load()` to parse `config.yml`.
2. All component objects are constructed: `Logger`, `GeoIP`, `AttackDetector`, `HoneypotEngine`.
3. `HoneypotEngine.start()` opens one `asyncio` TCP server per enabled service.
4. The Flask dashboard is launched in a daemon thread (separate from the event loop).
5. The event loop runs until the user sends `SIGINT` (Ctrl+C), at which point `HoneypotEngine.stop()` closes all servers cleanly.

## Process boundaries

Everything except the dashboard runs inside the main asyncio event loop. Flask runs in its own thread and reads the SQLite database directly -- it never touches shared in-memory state, so there is no locking complexity between the dashboard and the honeypot engine.

## Configuration-driven behavior

No service is hardcoded as active. Every listener is gated by the `enabled` field in `config.yml`. Adding a new service requires only enabling it in config and registering a handler in `engine.py`'s `SERVICE_HANDLERS` dict.

## Further reading

- [Component relationships](component-relationships.md)
- [Async architecture explained](async-architecture-explained.md)
- [Data flow walkthrough](data-flow-walkthrough.md)
