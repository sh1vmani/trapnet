# SSH Protocol

SSH (Secure Shell) runs on TCP port 22 and is one of the most heavily scanned services on the internet. Every exposed SSH server receives credential brute-force attempts within minutes of going live.

## How the handshake works

The SSH handshake has two distinct phases: version negotiation and key exchange.

**Version negotiation** is purely text-based. The server sends a single line:

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n
```

The client responds with its own version string in the same format. Both sides then know which protocol version and software they are dealing with.

**Key exchange** begins immediately after. The client and server exchange `SSH_MSG_KEXINIT` packets listing their supported algorithms, negotiate a shared secret using Diffie-Hellman, and derive session keys. Only after key exchange completes does authentication begin.

Authentication uses several possible methods: `publickey`, `password`, `keyboard-interactive`, and `gssapi`. Most brute-force attacks use the `password` method, which submits a plaintext password encrypted under the session keys.

## What trapnet does

trapnet sends the SSH banner and reads up to 1024 bytes of the client's response:

```python
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
```

This is the exact banner string emitted by OpenSSH 8.9 on Ubuntu 22.04. Scanners that check software versions before attempting known exploits will see a plausible target.

trapnet does not implement the key exchange. After reading the client's initial packet, it closes the connection. Most scanning tools send their version string and the first `SSH_MSG_KEXINIT` packet immediately, before waiting for anything further. That initial packet is what trapnet captures and logs.

## Why SSH is valuable for honeypots

SSH is a credential magnet. Attackers maintain large lists of username/password pairs and attempt them systematically. Even a 10-minute log from a public IP will contain hundreds of attempts at `root`, `admin`, `ubuntu`, `pi`, and other common accounts.

The version string in the banner also lets you observe which vulnerability scanners are checking for specific CVEs before attempting them. A scanner probing for CVE-2023-38408 (OpenSSH forwarded ssh-agent exploitation) will send a recognizable pattern immediately after the banner exchange.

## Common attacker behaviors

**Port knocking avoidance.** Many credential stuffers skip hosts that do not respond on port 22 within a very short timeout. They are optimizing for throughput, not stealth.

**Version fingerprinting.** Tools like Nmap run service detection probes that parse the version string and emit a structured fingerprint. The `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` banner will be identified as OpenSSH 8.9 on Linux.

**Key exchange detection.** More sophisticated scanners will attempt the full key exchange. These are usually automated exploit frameworks checking whether a target is vulnerable to a specific CVE before launching a payload.

## Further reading

- [How attackers scan networks](../01-concepts/how-attackers-scan-networks.md)
- [How Nmap is detected](../05-detection/how-nmap-is-detected.md)
- [How Metasploit is detected](../05-detection/how-metasploit-is-detected.md)
- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
