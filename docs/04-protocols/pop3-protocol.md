# POP3 Protocol

POP3 (Post Office Protocol version 3) runs on TCP port 110. It is a protocol for retrieving email from a mail server. Despite largely being replaced by IMAP, POP3 servers remain common in corporate environments and on hosted email platforms. POP3 credentials give attackers access to email, which is often a stepping stone to password resets on other services.

## How POP3 authentication works

POP3 uses a command/response model. The server sends a greeting starting with `+OK`, and the client authenticates using `USER` and `PASS` commands:

```
S: +OK POP3 server ready\r\n
C: USER alice@example.com\r\n
S: +OK\r\n
C: PASS secretpassword\r\n
S: -ERR Authentication failed\r\n
```

Responses beginning with `+OK` indicate success. Responses beginning with `-ERR` indicate failure. The credentials are transmitted in plain text.

After a successful `PASS`, the client uses commands like `STAT` (message count), `LIST` (message sizes), `RETR N` (retrieve message N), and `DELE N` (mark message N for deletion).

## What trapnet does

trapnet emulates a standard POP3 server:

```python
POP3_BANNER    = b"+OK POP3 server ready\r\n"
POP3_USER_OK   = b"+OK\r\n"
POP3_PASS_FAIL = b"-ERR Authentication failed\r\n"
```

After the banner, trapnet reads the first line. If it begins with `USER`, it extracts the username (everything after `USER `), sends `+OK`, reads the password line, extracts the password (everything after `PASS `), then sends `-ERR Authentication failed`. Both the username and password are logged.

## Why email credentials are high-value targets

Email accounts are used for password reset on most other services. An attacker with an email username and password can:

- Reset passwords on banking, e-commerce, and social media accounts linked to that email address.
- Search the inbox for other credentials sent via email.
- Use the account to send phishing email that passes SPF/DKIM checks.
- Access corporate communications and documents.

This makes POP3 credential attempts a more serious indicator than equivalent attempts on a database service, even though the protocol itself is simpler.

## POP3S

POP3S (POP3 over TLS) runs on port 995. trapnet does not emulate POP3S; port 110 is the plain-text variant. Most modern email clients use either IMAP or POP3S rather than plain POP3, so connections to port 110 skew toward automated scanners and legacy configurations.

## Common attacker behaviors

**Email address as username.** Unlike most protocols where usernames are short identifiers, POP3 is often tested with full email addresses. Credential lists targeting POP3 frequently include `user@domain.com` format usernames.

**Spraying common passwords.** The same common passwords used for SSH and FTP appear in POP3 attempts: `123456`, `password`, `letmein`, `admin`.

**Automated credential validation.** Attackers who acquire bulk email/password pairs from data breaches validate them across POP3 and IMAP before selling or using them, because many users reuse passwords.

## Further reading

- [SMTP protocol](smtp-protocol.md)
- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
