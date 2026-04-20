# engine.py Explained

`trapnet/core/engine.py` is the central coordinator that turns a config into a set of live TCP listeners.

## HoneypotEngine

`HoneypotEngine` holds references to four dependencies:

- `_config` -- the validated Config object
- `_logger` -- the Logger instance
- `_detector` -- the AttackDetector instance
- `_geoip` -- the GeoIP module

It stores the list of `asyncio.AbstractServer` objects it creates in `_servers`, so it can shut them all down cleanly in `stop()`.

## SERVICE_HANDLERS

The module-level dict maps service names to handler functions:

```python
SERVICE_HANDLERS = {
    "ssh":   svc_module.handle_ssh,
    "ftp":   svc_module.handle_ftp,
    ...
}
```

This is the only place where a service name from `config.yml` is connected to executable code. Adding support for a new protocol means adding an entry here and writing a handler in `services.py`.

## _make_handler

`asyncio.start_server()` expects a plain `async def callback(reader, writer)` function with no other arguments. `_make_handler()` wraps a protocol handler in a closure that injects the engine's dependencies:

```python
def _make_handler(self, handler_fn):
    async def _handler(reader, writer):
        src_ip = writer.get_extra_info("peername")[0]
        enriched = _EnrichedLogger(self._logger, self._geoip, src_ip)
        await handler_fn(reader, writer, enriched, self._detector, self._config)
    return _handler
```

This pattern avoids global state. Each handler call gets its own `_EnrichedLogger` bound to the current connection's source IP.

## _EnrichedLogger

`_EnrichedLogger` is a thin wrapper that defers GeoIP lookup to log time rather than connection-open time. The GeoIP API call happens only when `log_connection()` is called, which is after the protocol handshake is complete. This means:

- the attacker's first byte arrives with no added latency
- the GeoIP rate limiter cannot delay the handshake

## start()

`start()` iterates `config.services`. For each enabled service with a known handler, it calls `asyncio.start_server()`. If the bind fails (port already in use, permission denied), it logs a warning and skips that service rather than aborting -- the other services still start.

After all servers are up, it prints a startup summary and calls `asyncio.gather(*(s.serve_forever() ...))`, which runs the event loop indefinitely.

## stop()

`stop()` closes each server and waits for all active connections on that server to finish. It is called from `__main__.py`'s shutdown handler when `SIGINT` is received.

## Further reading

- [services.py explained](services-explained.md)
- [Async architecture explained](../02-architecture/async-architecture-explained.md)
- [Data flow walkthrough](../02-architecture/data-flow-walkthrough.md)
