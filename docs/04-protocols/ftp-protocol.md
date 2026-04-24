# FTP Protocol

FTP (File Transfer Protocol) runs on TCP port 21. Despite its age and the fact that all traffic is unencrypted, FTP servers remain common on internal networks and embedded devices. It is a frequent target for credential brute-forcing.

## How FTP authentication works

FTP uses a command/response model. Every command is a plain-text keyword followed by optional arguments and `\r\n`. Every response is a three-digit code followed by a human-readable message.

The authentication exchange:

1. Server sends a greeting: `220 (vsFTPd 3.0.5)\r\n`
2. Client sends `USER <username>\r\n`
3. Server responds with `331 Please specify the password.\r\n`
4. Client sends `PASS <password>\r\n`
5. Server responds with `230 Login successful.\r\n` or `530 Login incorrect.\r\n`

The credentials are transmitted in plain text on the wire. This is why FTP is considered insecure for any public-facing use.

## What trapnet does

trapnet emulates a vsFTPd 3.0.5 server:

```python
FTP_BANNER      = b"220 (vsFTPd 3.0.5)\r\n"
FTP_PASS_PROMPT = b"331 Please specify the password.\r\n"
FTP_FAIL        = b"530 Login incorrect.\r\n"
```

When a connection arrives, trapnet sends the banner and reads the first line from the client. If that line begins with `USER`, it extracts the username, sends the password prompt, reads the password line, and extracts the password. It then always sends `530 Login incorrect.` regardless of what was submitted. Both the username and password are captured and logged as a `credentials` field in the event record.

## Response code meanings

- `220` means "Service ready." It is the first response any FTP server sends.
- `331` means "Username OK, send password."
- `530` means "Not logged in." It is the correct response for a failed authentication.

## Common attacker behaviors

**Anonymous login.** Many FTP scanners first attempt `USER anonymous` followed by `PASS anonymous@` or an empty password. Anonymous FTP was common on early internet file repositories. Scanners still check for it.

**Default credentials.** After anonymous, attackers try default credentials for common FTP software: `admin:admin`, `ftp:ftp`, `ftpuser:ftpuser`, and manufacturer-specific defaults for embedded devices and routers.

**FTPS probing.** Some scanners send a TLS `ClientHello` to port 21 to check for Explicit FTPS. trapnet does not handle TLS, so these connections produce a non-matching payload and close.

## Further reading

- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
- [How attackers scan networks](../01-concepts/how-attackers-scan-networks.md)
