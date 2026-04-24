# SMTP Protocol

SMTP (Simple Mail Transfer Protocol) runs on TCP port 25 for server-to-server mail relay, and on port 587 for authenticated client submission. trapnet listens on port 25 and emulates a Postfix mail server. SMTP honeypots capture spam relay attempts and email credential theft.

## How SMTP authentication works

SMTP uses the same command/response model as FTP. The session begins with a server greeting, then proceeds through a negotiation phase before any authentication occurs.

A typical authenticated SMTP session:

```
S: 220 mail.example.com ESMTP Postfix\r\n
C: EHLO client.example.com\r\n
S: 250-mail.example.com\r\n250 OK\r\n
C: AUTH LOGIN\r\n
S: 334 Username:\r\n
C: <base64-encoded username>\r\n
S: 334 Password:\r\n
C: <base64-encoded password>\r\n
S: 535 5.7.8 Authentication failed\r\n
```

The `EHLO` command (Extended HELO) announces that the client supports SMTP extensions including AUTH. The `334` responses are server prompts asking for the next credential component. Credentials are base64-encoded but not encrypted in any way.

## What trapnet does

trapnet sends a Postfix banner and handles the EHLO/AUTH exchange:

```python
SMTP_BANNER    = b"220 mail.example.com ESMTP Postfix\r\n"
SMTP_EHLO_RESP = b"250-mail.example.com\r\n250 OK\r\n"
SMTP_AUTH_FAIL = b"535 5.7.8 Authentication failed\r\n"
```

After the banner, trapnet reads the first client line. If it begins with `EHLO`, it sends the EHLO response and then reads another line. If that line begins with `AUTH`, it sends the two `334` prompts to collect the base64 username and password. The credentials are decoded and logged. The session always ends with `535 5.7.8 Authentication failed.`

## EHLO vs HELO

`HELO` is the original SMTP greeting. `EHLO` is the extended version defined in RFC 1869. A server that responds to `EHLO` is indicating that it supports SMTP extensions, including authentication methods (AUTH), encryption negotiation (STARTTLS), and message size limits. Modern clients always use `EHLO`. A scanner that sends `HELO` is either very old or deliberately checking for legacy server behavior.

## Common attacker behaviors

**Open relay testing.** Before AUTH was standard, many SMTP servers relayed mail for any sender. Spammers still scan for open relays. They typically try to send a message from an external address to an external address through the server without authenticating.

**Credential stuffing.** Email credentials are valuable because they often work for more than just email. Attackers test harvested username/password pairs against SMTP servers to validate them.

**Username enumeration.** Some SMTP configurations respond differently to `RCPT TO:` for valid vs. invalid addresses. Scanners use this to enumerate valid email accounts before launching targeted phishing.

## Further reading

- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
- [Threat intelligence basics](../01-concepts/threat-intelligence-basics.md)
