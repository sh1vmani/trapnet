# VNC Protocol

VNC (Virtual Network Computing) runs on TCP port 5900. It provides graphical remote desktop access and is used on Linux, macOS, and Windows systems. Exposed VNC instances are valuable targets because they provide full desktop control.

## How VNC authentication works

VNC uses the RFB (Remote Framebuffer) protocol. The handshake sequence:

1. Server sends protocol version: `RFB 003.008\n`
2. Client responds with its supported version.
3. Server sends the list of supported security types as a 1-byte count followed by type bytes.
4. Client selects one security type by sending the 1-byte type number.
5. For security type 2 (VNC Authentication), the server sends a 16-byte random challenge.
6. Client encrypts the challenge using DES with the password as the key and sends back the 16-byte encrypted response.
7. Server sends a 4-byte result: `\x00\x00\x00\x00` for success or `\x00\x00\x00\x01` for failure.

The VNC password is used as a DES key with weak bit reversal. Each byte of the password has its bits reversed before use as a DES key byte. This is a well-known weakness in the VNC authentication scheme.

## What trapnet does

trapnet implements the full VNC authentication sequence:

```python
VNC_VERSION    = b"RFB 003.008\n"
VNC_SEC_TYPES  = b"\x01\x02"        # 1 type available: type 2 (VNC Authentication)
VNC_CHALLENGE  = b"\x00" * 16       # 16-byte challenge
VNC_AUTH_FAILED = b"\x00\x00\x00\x01"  # auth result: failed
```

The exchange:

1. trapnet sends `RFB 003.008\n`.
2. trapnet reads the 12-byte client version string.
3. trapnet sends the security type list (`\x01\x02` = one type, type 2).
4. trapnet reads the 1-byte type selection.
5. trapnet sends the 16-byte challenge (all zeros).
6. trapnet reads the 16-byte encrypted auth response.
7. trapnet sends the failure result.

The challenge being all zeros is intentional. A real VNC server would use a random challenge. A zero challenge means the encrypted response reveals information about the password (DES of zeros with the password as the key), but trapnet never performs this analysis. The logged payload includes both the client version and the auth response.

## Security type 2 weakness

VNC Authentication (type 2) uses DES, which has a 56-bit effective key size. The password is truncated to 8 characters. The bit-reversal of the key bytes is a protocol quirk that makes VNC passwords incompatible with standard DES implementations without the reversal step. Despite this, the auth scheme is weak by modern standards and has been broken offline with GPU acceleration.

More secure VNC implementations use security type 19 (VeNCrypt), which wraps the session in TLS. trapnet only implements type 2.

## Common attacker behaviors

**Version probing.** Many scanners connect, read the RFB version string, and disconnect immediately. This confirms that VNC is running without attempting authentication.

**Password brute-force.** VNC has no rate limiting by default and no account lockout. Automated tools try hundreds of passwords per second against exposed VNC servers.

**Known-password attempts.** Like Telnet on IoT devices, VNC on embedded hardware often uses factory-default passwords that scanners carry in their wordlists.

## Further reading

- [RDP protocol](rdp-protocol.md)
- [Credential stuffing patterns](../05-detection/credential-stuffing-patterns.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
