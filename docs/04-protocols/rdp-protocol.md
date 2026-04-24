# RDP Protocol

RDP (Remote Desktop Protocol) runs on TCP port 3389. It is the primary remote management protocol for Windows systems. Exposed RDP is one of the most common initial access vectors in ransomware incidents.

## How RDP connects

RDP uses a layered protocol stack. From bottom to top:

1. **TPKT** (RFC 1006) - wraps ISO transport packets over TCP. Every TPKT packet starts with a 4-byte header: version (always `0x03`), reserved (`0x00`), and a 2-byte length.

2. **X.224** - handles connection establishment. The client sends a Connection Request PDU; the server responds with a Connection Confirm PDU.

3. **MCS (Multipoint Communication Service)** - multiplexes virtual channels over the single TCP connection.

4. **RDP security layer or TLS** - encrypts and authenticates the session.

The first packet from a client is an X.224 Connection Request. The server's first response is an X.224 Connection Confirm. Before Network Level Authentication (NLA) was added, this sequence was followed immediately by credential prompting. With NLA enabled, CredSSP negotiation happens before the desktop is shown.

## What trapnet sends

trapnet reads the incoming client packet and responds with an X.224 Connection Confirm PDU:

```python
RDP_CONFIRM = (
    b"\x03\x00\x00\x13"   # TPKT: version 3, length 19
    b"\x0e"                # X.224 LI: 14 bytes follow
    b"\xd0"                # X.224 code: connection confirm (0xD0)
    b"\x00\x00"            # destination reference
    b"\x12\x34"            # source reference
    b"\x00"                # class and options
    b"\x02"                # RDP negotiation response type
    b"\x00"                # flags
    b"\x08\x00"            # response length 8
    b"\x00\x00\x00\x00"   # selected protocol: classic RDP (no TLS/NLA)
)
```

Total length is 19 bytes, matching the TPKT length field. The `0xd0` code is the X.224 Connection Confirm. The `selected protocol: 0x00000000` field indicates classic RDP without TLS or NLA. A real server would typically select TLS or NLA here; returning classic RDP causes many clients and scanners to immediately attempt authentication, which generates more visible attacker behavior.

## Why port 3389 is so valuable for threat intelligence

RDP scanning never stops. Within minutes of a public IP having port 3389 open, automated scanners begin attempting credentials. The payloads reveal:

- Which RDP client or scanning tool is making the connection (from the negotiation flags)
- Whether the scanner supports NLA (more sophisticated scanners will attempt CredSSP)
- Whether the scanner is probing for specific CVEs (e.g., CVE-2019-0708 BlueKeep, CVE-2019-1182 DejaBlue)

## BlueKeep and related CVEs

CVE-2019-0708 (BlueKeep) was a pre-authentication remote code execution vulnerability in RDP. It affected Windows XP through Server 2008 R2. Exploit attempts are still observed years after patching, particularly from automated frameworks. The Metasploit module for BlueKeep sends a recognizable probe pattern that trapnet's detector checks for.

## Common attacker behaviors

**Credential spraying.** Common combinations like `administrator:Password1`, `administrator:Welcome1`, and domain names as passwords are tried at high rates.

**NLA bypass probing.** Scanners check whether the server requires NLA. Classic RDP without NLA allows the login screen to appear before authentication, which historically enabled some credential harvesting attacks.

**BlueKeep scanning.** Automated scanners check for the pre-auth memory corruption vulnerability pattern before attempting exploitation.

## Further reading

- [How Metasploit is detected](../05-detection/how-metasploit-is-detected.md)
- [How Nmap is detected](../05-detection/how-nmap-is-detected.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
