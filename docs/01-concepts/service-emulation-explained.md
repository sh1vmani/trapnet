# Service Emulation Explained

trapnet does not run real SSH, MySQL, or Redis servers. It runs Python coroutines that speak just enough of each protocol to satisfy a scanner or an automated attack tool. This document explains what service emulation is, how trapnet implements it, and what its limits are.

## What emulation means here

A real SSH server negotiates keys, encrypts the channel, and runs a shell. trapnet's SSH emulator sends one line:

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n
```

Then it reads whatever the client sends, logs it, closes the connection, and waits for the next one. That is the entire implementation.

This is sufficient because the goal is not to interact with the attacker but to record what they send. A scanner reading the banner records "SSH 8.9p1 on Ubuntu 22.04." An exploit tool sends its payload. trapnet captures both.

## Protocol fidelity

Each service emulator is calibrated to the real protocol for the first exchange:

- **MySQL** sends a 77-byte Protocol 10 handshake with the correct capability flags, auth plugin name, and version string. A MySQL client will read it without error and proceed to send authentication data.
- **PostgreSQL** reads the startup message from the client, sends an MD5 authentication request, reads the password response, then sends a fatal authentication error with the correct SQLSTATE code.
- **MongoDB** builds a valid BSON OP_MSG frame with `{ok: 0, errmsg: "Unauthorized"}`. A real MongoDB driver will parse it correctly.
- **SMB** sends an SMB2 header with the correct magic bytes and structure size. A Windows client will recognize it as a valid SMB2 server response.
- **RDP** sends an X.224 connection confirm PDU with valid TPKT framing. An RDP client advances to the next negotiation step.

This level of fidelity is important for capturing attacker payloads. If the initial response is malformed, the client may disconnect before sending its authentication or exploit data.

## What emulation does not do

- It does not allow login. Every authentication attempt fails.
- It does not support multi-step sessions beyond what is needed to capture a credential pair.
- It does not implement encryption (TLS, SSH key exchange, etc.).
- It does not emulate errors the way a real server would for unexpected protocol states.

## Timeout behavior

Every read is wrapped in `asyncio.wait_for` with a 10-second timeout. If a client connects and sends nothing, trapnet records an empty payload and closes the connection after 10 seconds. This prevents idle connections from consuming resources.

## Concurrency

Each service runs as an `asyncio.start_server` listener. Python's asyncio event loop handles thousands of concurrent connections on a single thread by switching between coroutines whenever one is waiting on I/O. There is no per-connection thread overhead.

## Further reading

- [Async architecture explained](../02-architecture/async-architecture-explained.md)
- [Services code walkthrough](../03-code-walkthrough/services-explained.md)
- Protocol-specific details in [04-protocols/](../04-protocols/)
