# PostgreSQL Protocol

PostgreSQL runs on TCP port 5432. It is a widely used open-source relational database. Like MySQL, exposed PostgreSQL instances are targeted for data theft and for leveraging database-level features to gain server access.

## How PostgreSQL authentication works

PostgreSQL uses a message-based binary protocol. Messages have a one-byte type code, a 4-byte length field (including the length field itself), and a payload.

The connection sequence:

1. Client sends a `StartupMessage` containing the protocol version and connection parameters (username, database name).
2. Server responds with an authentication request. The type determines the auth method: `0` = trust (no password), `3` = cleartext password, `5` = MD5 password, `10` = SASL.
3. Client responds with a password message.
4. Server responds with `AuthenticationOK` (type `R`, subtype `0`) or an `ErrorResponse`.

## What trapnet sends

trapnet first reads the client's `StartupMessage`, then responds with an MD5 authentication request:

```python
PG_AUTH_REQUEST = (
    b"R"                  # message type: AuthenticationRequest
    b"\x00\x00\x00\x0c"  # length 12
    b"\x00\x00\x00\x05"  # auth type 5: MD5 password
    b"\x1a\x2b\x3c\x4d"  # MD5 salt (4 bytes)
)
```

Auth type `5` is MD5 password authentication. The 4-byte salt is mixed into the hash: the client computes `MD5("md5" + MD5(password + username) + salt)` and sends it as a hex string prefixed with "md5".

After reading the client's password response, trapnet sends an ErrorResponse:

```python
PG_AUTH_ERROR = (
    b"E"                  # message type: ErrorResponse
    b"\x00\x00\x00\x46"  # length 70
    b"SFATAL\x00"         # severity field
    b"C28P01\x00"         # SQLSTATE: invalid_password
    b"Mpassword authentication failed for user \"postgres\"\x00"
    b"\x00"               # message terminator
)
```

SQLSTATE `28P01` is the PostgreSQL-specific code for invalid password. The error message format uses field identifiers (`S` for severity, `C` for code, `M` for message) followed by null-terminated values.

## COPY TO / Large Objects

PostgreSQL has features that make it dangerous when exposed. `COPY TO PROGRAM` executes a shell command and writes the output as SQL. `pg_read_file()` and large object functions can read files from the server's filesystem. Attackers who gain PostgreSQL access as a superuser can escalate to OS-level access using these features. This is why exposed PostgreSQL is treated similarly to exposed Redis in terms of severity.

## Why two reads before the error

trapnet does two reads: one for the StartupMessage and one for the password response. This is because PostgreSQL clients will not send the password until they receive the auth challenge. A connection that only gets an error before the challenge will not have sent any credentials. The two-read pattern ensures that scanning tools that perform the full handshake have their response captured.

## Common attacker behaviors

**Superuser probing.** Almost all PostgreSQL brute-force attempts use `postgres` as the username, which is the default superuser. The error message in `PG_AUTH_ERROR` references `postgres` explicitly, matching what a real server would return.

**SCRAM vs MD5.** PostgreSQL 14 and later default to SCRAM-SHA-256 authentication instead of MD5. Scanners that only implement MD5 auth may fail to proceed when encountering a SCRAM challenge. Returning MD5 (`auth type 5`) keeps compatibility with older clients and scanners.

## Further reading

- [MySQL handshake](mysql-handshake.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
- [Network isolation best practices](../06-security-concepts/network-isolation-best-practices.md)
