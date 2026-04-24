# Telnet Protocol

Telnet runs on TCP port 23. It is a legacy remote terminal protocol that predates SSH by decades. All traffic including credentials is transmitted in plain text. Despite being functionally obsolete for secure remote administration, Telnet remains active on embedded devices, routers, switches, and IoT hardware where it is the default management interface.

## How Telnet works

Telnet has two layers: option negotiation and terminal data.

**Option negotiation** happens at the start of the connection. Both sides exchange three-byte `IAC` (Interpret As Command) sequences to negotiate terminal type, line mode, echo behavior, and other options. `IAC` is byte `0xFF`. A negotiation sequence is `IAC WILL/WONT/DO/DONT <option>`.

**Terminal data** is plain text. After negotiation, the server sends a login prompt and reads the username and password as plain text lines.

A typical server-initiated negotiation before the login prompt:

```
\xff\xfd\x01   IAC DO ECHO         (server asks client to not echo)
\xff\xfd\x1f   IAC DO NAWS         (server asks for window size)
\xff\xfb\x01   IAC WILL ECHO       (server will handle echo)
\xff\xfb\x03   IAC WILL SGA        (server will suppress go-ahead)
```

## What trapnet does

trapnet sends a negotiation block followed by a login banner and prompt:

```python
TELNET_NEGOTIATION = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03"
TELNET_BANNER      = b"Ubuntu 22.04 LTS\r\nlogin: "
TELNET_PASS_PROMPT = b"Password: "
TELNET_FAIL        = b"Login incorrect\r\n"
```

After sending the negotiation and banner, trapnet reads the first line as the username, sends the password prompt, reads the second line as the password, then sends `Login incorrect` and closes. Both credentials are logged.

## Why IoT devices still use Telnet

Telnet persists on IoT hardware because:

- The devices predate SSH and were never updated.
- Adding SSH increases firmware size and CPU requirements on resource-constrained hardware.
- Manufacturers ship with Telnet enabled for factory support access and never disable it.
- Default credentials are hard-coded and rarely changed by users.

The Mirai botnet in 2016 scanned the entire internet for Telnet on port 23 using a list of 61 default credential pairs and infected hundreds of thousands of IoT devices. Variants of Mirai still operate, and port 23 continues to see constant scanning.

## Common attacker behaviors

**Default credential lists.** Telnet scanners carry long lists of manufacturer-specific default credentials. Common pairs include `admin:admin`, `root:root`, `root:` (empty password), `user:user`, `admin:1234`, and device-specific defaults from router and camera manufacturers.

**Rapid sequential attempts.** IoT-targeting scanners often attempt multiple credentials per connection before moving on, because many embedded Telnet daemons allow retry without disconnecting.

**Payload delivery after login.** In a real Telnet session, an attacker who successfully logs in will typically run `busybox MIRAI` or a download command to fetch a malware payload. These command strings are recognizable in the login username field if the attacker is reusing the same payload without proper sequencing.

## Further reading

- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
- [Threat intelligence basics](../01-concepts/threat-intelligence-basics.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
