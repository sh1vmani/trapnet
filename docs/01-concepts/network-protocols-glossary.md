# Network Protocols Glossary

Definitions for the protocols and terms used throughout trapnet documentation.

---

**ASCII** - American Standard Code for Information Interchange. A 7-bit character encoding used in most plaintext protocols (FTP, SMTP, POP3, Telnet, Redis).

**Banner** - The greeting message a server sends immediately after a TCP connection is established, before the client sends anything. Banners typically include the software name and version (`220 (vsFTPd 3.0.5)`, `SSH-2.0-OpenSSH_8.9p1`).

**BSON** - Binary JSON. MongoDB's wire format. Documents are length-prefixed binary structures rather than text.

**Daemon** - A background process that listens for and handles network connections. In trapnet, each service emulator is effectively a daemon listening on its configured port.

**FTP** - File Transfer Protocol (RFC 959). Plaintext protocol on port 21. Uses a command channel for authentication and a separate data channel for file transfers. trapnet emulates only the command channel.

**HTTP** - HyperText Transfer Protocol (RFC 7230). Text-based request/response protocol on port 80. Requests begin with a method line (`GET / HTTP/1.1`), headers, and an optional body.

**HTTPS** - HTTP over TLS. Port 443. trapnet accepts the raw TCP connection and responds with an HTTP response without performing a TLS handshake. This is intentional: it captures plaintext probes sent to the port.

**IP** - Internet Protocol. The network-layer protocol that routes packets between hosts. Every connection trapnet receives has a source IP address.

**Memcached** - A distributed in-memory cache. Uses a simple plaintext protocol on port 11211. The `stats` command returns server statistics; trapnet returns a minimal stats response.

**MongoDB** - A document-oriented database. Uses a binary protocol (wire protocol) on port 27017. trapnet responds with a valid BSON OP_MSG error frame.

**MySQL** - A relational database. Uses a binary Protocol 10 handshake on port 3306. The server sends a handshake packet first; the client responds with authentication data.

**POP3** - Post Office Protocol version 3 (RFC 1939). Plaintext mail retrieval on port 110. Authentication uses `USER` and `PASS` commands.

**Port** - A 16-bit number (1-65535) that identifies a specific service on a host. Ports below 1024 are conventionally assigned to well-known services.

**PostgreSQL** - A relational database. Uses a binary message protocol on port 5432. The client sends a startup message; the server responds with an authentication request.

**RDP** - Remote Desktop Protocol. Microsoft's remote desktop protocol on port 3389. Uses X.224 connection confirmation followed by RDP negotiation.

**Redis** - An in-memory key-value store. Uses the RESP (REdis Serialization Protocol) text protocol on port 6379. Commands start with `*` (array).

**RFC** - Request for Comments. The document series that defines internet standards. Protocol behavior in trapnet is based on the relevant RFCs.

**RESP** - REdis Serialization Protocol. Simple text-based protocol used by Redis. Arrays start with `*`, bulk strings with `$`, simple strings with `+`, errors with `-`.

**SMB** - Server Message Block. Windows file sharing protocol on port 445. SMB2 uses a 64-byte fixed header structure.

**SMTP** - Simple Mail Transfer Protocol (RFC 5321). Plaintext email submission on port 25. Begins with a server greeting, then `EHLO`/`HELO`, then optional `AUTH`.

**SSH** - Secure Shell (RFC 4253). Encrypted remote shell protocol on port 22. The connection begins with plaintext version string exchange before encryption negotiates.

**TCP** - Transmission Control Protocol. Connection-oriented transport protocol. All trapnet services use TCP. A TCP connection involves a three-way handshake (SYN, SYN-ACK, ACK) before application data flows.

**Telnet** - An early remote login protocol (RFC 854). Plaintext, port 23. Begins with option negotiation bytes followed by a login prompt.

**TPKT** - A transport encapsulation for ISO protocols over TCP, used by RDP. Has a 4-byte header: version (1), reserved (1), length (2).

**TLS** - Transport Layer Security. The cryptographic protocol used by HTTPS, IMAPS, SMTPS, and others. trapnet does not implement TLS.

**UDP** - User Datagram Protocol. Connectionless transport protocol. trapnet does not emulate UDP services.

**VNC** - Virtual Network Computing. A remote desktop protocol on port 5900. Uses the RFB (Remote Framebuffer) protocol. The server sends a version string; the client responds with its version.

**X.224** - An ISO transport layer protocol used as the connection-establishment layer in RDP.
