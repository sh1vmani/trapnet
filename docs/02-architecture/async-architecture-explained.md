# Async Architecture Explained

trapnet is built on Python's `asyncio` library. Understanding why this matters helps you reason about the system's behavior under load and when reading the code.

## Why asyncio?

A honeypot is I/O-bound, not CPU-bound. It spends almost all of its time waiting for:

- incoming bytes from an attacker's connection
- a GeoIP HTTP response
- a disk write to complete

Threads are one way to handle many I/O operations concurrently, but they carry overhead per connection and require explicit locking around every shared data structure. `asyncio` handles many thousands of connections with a single thread by using cooperative scheduling: a coroutine runs until it hits an `await`, at which point the event loop runs something else.

## How the event loop is used

`HoneypotEngine.start()` calls `asyncio.start_server()` once per enabled service. Each call registers a callback with the event loop that fires whenever a new TCP connection arrives on that port.

When a connection arrives, the event loop calls the handler coroutine. The handler runs synchronously until it hits its first `await` (usually `reader.read()`). While it waits for the attacker's next byte, the event loop services other connections on other ports.

This means 50 simultaneous attackers on 15 different ports are handled concurrently by a single Python thread with no thread switching overhead.

## Blocking operations

Two operations would block the event loop if run directly: disk writes and the GeoIP HTTP request.

**Disk writes** in `Logger` use `asyncio.to_thread()`. This sends the write function to a thread pool executor and yields control back to the event loop while the write completes. The event loop does not block.

**GeoIP lookups** use `aiohttp`, which is natively async. Each lookup is an `await` expression that yields control while the HTTP response is in flight.

## The lock in AttackDetector

`AttackDetector` keeps a dict of per-IP event histories. Multiple handlers can call `analyze()` concurrently (one per active connection). The tracker dict is protected by an `asyncio.Lock`.

Because asyncio is single-threaded, the lock is only needed to guard against two coroutines interleaving their access during the same sequence of `await` points. Any code path that reads and then writes the tracker without an intervening `await` would be safe without a lock -- but using the lock makes the invariant explicit and robust to future changes.

The lock is created lazily (on first use rather than at `__init__` time) because creating an `asyncio.Lock` before the event loop is running raises an error in older Python versions.

## The dashboard thread

Flask is synchronous. Running it inside the event loop would block the entire honeypot while it handles HTTP requests. Instead, it runs in a `threading.Thread` (a daemon thread, so it exits automatically when the main process exits).

The dashboard only reads from SQLite. SQLite has its own internal locking, so reads from the Flask thread and writes from the logger thread do not conflict.

## What this means for errors

If a handler raises an unhandled exception, `asyncio` logs the traceback and closes that connection. The event loop continues running. Other connections on other ports are unaffected. The honeypot stays up even if one protocol handler has a bug.

## Further reading

- [Component relationships](component-relationships.md)
- [Data flow walkthrough](data-flow-walkthrough.md)
