# services.py Explained

`trapnet/core/services.py` contains one async handler function per emulated protocol. These functions are the core of what makes trapnet a honeypot rather than just a port listener.

## Handler signature

Every handler has the same signature:

```python
async def handle_ssh(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    logger,
    detector: AttackDetector,
    config: Config,
) -> None:
```

`reader` and `writer` are asyncio stream objects for the TCP connection. `logger` is the `_EnrichedLogger` instance for this connection (see `engine.py`). `detector` and `config` are shared across all connections.

## What each handler does

Every handler follows the same pattern:

1. Send the service banner (e.g., the SSH version string, FTP greeting, MySQL handshake).
2. Read the attacker's response, up to a safe maximum (typically 256-4096 bytes).
3. For protocols with authentication, send a credential prompt and read the response.
4. Always return an authentication failure, never success.
5. Call `detector.analyze()` with the payload.
6. Call `logger.log_connection()` with the assembled record.
7. Close the connection.

## Banners are realistic

The banners mimic specific real software versions:

- SSH: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`
- FTP: `220 (vsFTPd 3.0.5)`
- MySQL: Protocol 10 handshake with version string `5.7.43-log`
- PostgreSQL: MD5 authentication request followed by `FATAL: password authentication failed`

These are the same strings a real Ubuntu 22.04 server would emit. Scanners that fingerprint version strings before attempting exploits will see a plausible target.

## Protocol complexity varies

**Simple protocols** (SSH, FTP, Telnet) use plain text and can be handled with a few `reader.read()` and `writer.write()` calls.

**Binary protocols** (MySQL, PostgreSQL, MongoDB, Redis, SMB, RDP) require correctly structured binary frames. The constants in `services.py` (e.g., `MYSQL_HANDSHAKE`, `PG_AUTH_REQUEST`) are the exact byte sequences those protocols specify. Comments in the source explain how each packet is built.

## Why authentication always fails

If a handler ever returned success, the attacker would expect the protocol to continue past authentication into a real session. trapnet has no post-authentication state to maintain. Always returning failure keeps the emulation correct and keeps the codebase simple.

## Read limits

Every `reader.read()` call uses an explicit maximum byte count (e.g., `reader.read(256)`). This prevents a slow-loris or large-payload attack from holding a handler coroutine open indefinitely or consuming large amounts of memory.

## Further reading

- [SSH protocol](../04-protocols/ssh-protocol.md)
- [MySQL handshake](../04-protocols/mysql-handshake.md)
- [Service emulation explained](../01-concepts/service-emulation-explained.md)
