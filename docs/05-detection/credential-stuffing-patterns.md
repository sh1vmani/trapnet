# Credential Stuffing Patterns

Credential stuffing is the automated submission of username/password pairs harvested from data breaches against login endpoints. It is distinguished from brute-force attacks by its use of real credentials from previous breaches rather than dictionary words or generated combinations. trapnet captures and classifies credential stuffing with a confidence score of 0.75.

## What credential stuffing looks like on the wire

A credential stuffer connects to an authentication service, submits one or more credential pairs, observes the success or failure response, and moves on. The pattern repeated across thousands of IPs or focused from one IP looks like:

- Many sequential login attempts against the same service
- Usernames that are email addresses (from breach databases)
- Passwords that appear in known breach data (not just dictionary words)

At high rates from a single IP, it becomes detectable as a pattern.

## How trapnet detects it

trapnet tracks authentication attempts per service per IP in the last 30 seconds:

```python
auth_services = {"ssh", "ftp", "telnet", "pop3", "smtp"}

if service in auth_services:
    auth_events_30s = [e for e in events_last_30s if e[2] == service]
    if len(auth_events_30s) > 3:
        cred.append(f"{len(auth_events_30s)} login attempts on {service} in 30 seconds")
```

More than 3 authentication attempts on the same service from the same IP within 30 seconds is treated as a credential stuffing signal. This threshold is low by design; a legitimate user re-entering a password once or twice does not reach it, but any automated tool does.

The second signal checks for common passwords in the payload:

```python
common_passwords = [
    b"admin", b"password", b"123456", b"root",
    b"test", b"guest", b"12345678",
]

for pw in common_passwords:
    if pw in payload_lower:
        cred.append(f"common password string in payload: {pw.decode()!r}")
        break
```

These are the top entries from the most commonly found password lists. An attacker using one of these is either running a dictionary attack or validating breach credentials that happen to include common passwords.

## The difference between credential stuffing and brute force

**Brute force** generates all possible combinations or iterates through a dictionary wordlist. It does not require prior breach data. It is slower and less effective against accounts with strong passwords.

**Credential stuffing** uses real username/password pairs known to be valid somewhere. Because people reuse passwords across services, a 10% success rate against one service means a non-trivial success rate elsewhere. Brute force success rates against strong passwords are effectively zero; credential stuffing success rates are routinely 1-2%.

trapnet cannot distinguish between the two from the credential content alone, because many common passwords appear in both breach databases and dictionary wordlists. The behavioral signal (rate of attempts) is more reliable than the content signal.

## What the logged credentials reveal

When trapnet logs a credential pair, the `credentials` field contains `username:password` in plain text. Over time, aggregating these credentials reveals:

- Which credential lists are currently in circulation
- Whether the list targets specific services (email addresses suggest a mail-targeting campaign)
- Whether the same credentials appear across multiple source IPs (indicating the list is widely distributed)

This is threat intelligence that goes beyond individual event detection.

## Credential stuffing is not targeted

Credential stuffing against a honeypot carries no risk to real systems. The attacker is not attacking your actual services; they are validating credentials against whatever responds on these ports. The honeypot's value is in capturing the credentials and source IPs for analysis, not in preventing any specific harm.

## Further reading

- [SSH protocol](../04-protocols/ssh-protocol.md)
- [FTP protocol](../04-protocols/ftp-protocol.md)
- [Understanding confidence scores](understanding-confidence-scores.md)
- [Threat intelligence basics](../01-concepts/threat-intelligence-basics.md)
