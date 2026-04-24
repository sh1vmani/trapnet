# MySQL Handshake

MySQL runs on TCP port 3306. It is one of the most commonly exposed databases on the internet, often misconfigured to listen on all interfaces. Attackers frequently target it for data theft, ransomware deployment, and using the `LOAD DATA INFILE` feature to read local files.

## How the MySQL handshake works

Unlike HTTP or FTP, MySQL authentication uses a binary protocol. The server initiates the exchange:

1. Server sends a handshake packet (Protocol Version 10) including the server version string, a connection ID, and a challenge (auth plugin data) used for password hashing.
2. Client responds with a handshake response packet that includes the username, a hashed password (not the plaintext password), and capability flags.
3. Server responds with an OK packet (success) or an ERR packet (failure).

The password is hashed using SHA1 before transmission. The server sends a random 20-byte challenge; the client computes `SHA1(password) XOR SHA1(challenge + SHA1(SHA1(password)))`. This means the plaintext password is never sent on the wire during a standard MySQL connection.

## What trapnet sends

trapnet sends a real MySQL Protocol 10 initial handshake packet:

```python
MYSQL_HANDSHAKE = (
    b"\x4d\x00\x00\x00"            # packet length 77, sequence 0
    b"\x0a"                         # protocol version 10
    b"5.7.43-log\x00"               # server version string
    b"\x08\x00\x00\x00"             # connection ID
    b"\x52\x7b\x50\x3d\x4b\x2c\x4e\x44\x00"  # auth data part 1 + filler
    b"\xff\xf7"                     # capability flags lower
    b"\x21"                         # character set: utf8
    b"\x02\x00"                     # server status flags
    b"\xff\x81"                     # capability flags upper
    b"\x15"                         # auth plugin data length (21)
    b"\x00" * 10                    # reserved
    b"\x6d\x4f\x72\x3d\x42\x65\x72\x7a\x55\x31\x56\x00"  # auth data part 2
    b"mysql_native_password\x00"    # auth plugin name
)
```

After reading the client's handshake response, trapnet sends an error:

```python
MYSQL_AUTH_ERROR = (
    b"\x2d\x00\x00\x02"   # packet length 45, sequence 2
    b"\xff"                # error marker
    b"\x15\x04"            # error code 1045 (little-endian)
    b"\x23"                # SQL state marker #
    b"28000"               # SQL state: access denied
    b"Access denied for user 'root'@'host'"
)
```

Error 1045 with SQL state `28000` is the standard MySQL "Access denied" response. A real MySQL server returns exactly this when authentication fails.

## Packet framing

MySQL packets have a 4-byte header: 3 bytes for the payload length (little-endian) and 1 byte for the sequence number. Sequence 0 is the initial server greeting; sequence 1 is the client response; sequence 2 is the server's auth result. Malformed packets that violate this framing will be rejected by a real MySQL client driver.

## What the client response reveals

The handshake response packet from the client contains:

- The client's capability flags (which MySQL features it supports)
- The username being attempted
- The hashed password response to the server's challenge
- The name of the default database (if any)
- The character set

trapnet logs the raw bytes as a hex payload. The username can be extracted from the packet at a fixed offset if needed for deeper analysis.

## Common attacker behaviors

**Root access attempts.** The overwhelming majority of MySQL brute-force attempts use the `root` username. This matches the error string in `MYSQL_AUTH_ERROR`.

**Automated exploit kits.** Some attack frameworks check for unauthenticated MySQL access before attempting to deploy cryptocurrency miners or ransomware via `SELECT INTO OUTFILE` or `LOAD DATA INFILE`.

**Version-specific CVE probing.** Attackers that fingerprint `5.7.43-log` may check for known CVEs in MySQL 5.7. The `-log` suffix indicates binary logging is enabled, which was a common configuration.

## Further reading

- [Services explained](../03-code-walkthrough/services-explained.md)
- [How attackers scan networks](../01-concepts/how-attackers-scan-networks.md)
- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
