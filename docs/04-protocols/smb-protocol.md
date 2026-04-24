# SMB Protocol

SMB (Server Message Block) runs on TCP port 445. It is the primary file sharing protocol on Windows networks. EternalBlue (CVE-2017-0144) turned SMB into one of the most targeted services in the history of internet scanning. WannaCry, NotPetya, and many ransomware campaigns used it as their primary propagation mechanism.

## How SMB negotiation works

SMB2 is the modern version of the protocol, introduced in Windows Vista. SMB2 sessions begin with a Negotiate request:

1. Client sends an SMB2 Negotiate request listing the SMB dialects it supports.
2. Server responds with an SMB2 Negotiate response selecting a dialect and providing session parameters.
3. Client sends an SMB2 Session Setup request to authenticate.
4. Server responds with an authentication challenge or error.

Every SMB2 packet has a 64-byte fixed-size header. The header starts with the magic bytes `\xfeSMB` (the `\xfe` distinguishes SMB2 from SMB1, which uses `\xffSMB`). Before the SMB2 header, packets are wrapped in a 4-byte NetBIOS session service header that encodes the payload length.

## What trapnet sends

trapnet reads the incoming packet and replies with a minimal SMB2 header:

```python
SMB2_RESPONSE = (
    b"\x00\x00\x00\x40"   # NetBIOS session: length 64
    b"\xfeSMB"             # SMB2 protocol id
    b"\x40\x00"            # header structure size (always 64)
    b"\x00\x00"            # credit charge
    b"\x00\x00\x00\x00"   # NT status: success
    b"\x00\x00"            # command: negotiate
    b"\x01\x00"            # credits granted
    b"\x00\x00\x00\x00"   # flags
    b"\x00\x00\x00\x00"   # next command offset
    b"\x00" * 8            # message ID
    b"\x00" * 4            # process ID
    b"\x00" * 4            # tree ID
    b"\x00" * 8            # session ID
    b"\x00" * 16           # signature
)
```

This is the minimum valid SMB2 header. After receiving it, most clients and scanners will close the connection, having confirmed that an SMB2 server is listening on the port.

## EternalBlue and the SMB1 probe

EternalBlue exploited a bug in SMB1's handling of transaction subcommands. The exploit sends a specific malformed SMB1 packet to port 445. trapnet's detector checks the raw payload bytes:

```python
if service == "smb" and payload.startswith(b"\x00\x00\x00\x2f\xff\x53\x4d\x42"):
    msf.append("EternalBlue SMB probe signature")
```

The bytes `\xff\x53\x4d\x42` are the SMB1 magic bytes (`\xffSMB`). An SMB2 server that receives an SMB1 packet is being probed for compatibility or for the EternalBlue vulnerability. This is a high-confidence Metasploit indicator.

## Why SMB honeypots see so much traffic

Port 445 is blocked at the network perimeter by most ISPs and cloud providers, but on internal networks it is always open. Malware that spreads via SMB does not need an external scan; it scans laterally through LAN segments. A trapnet instance on an internal network segment will see this lateral movement immediately.

On external IPs, SMB traffic still arrives from ISPs that do not filter it and from compromised hosts in cloud environments.

## Common attacker behaviors

**SMB1 negotiation.** Many scanners begin with an SMB1 Negotiate request to check for legacy compatibility. WannaCry-style worms exclusively use SMB1.

**EternalBlue probing.** Automated frameworks check for the EternalBlue pattern before attempting the exploit. The probe pattern is highly distinctive.

**Credential relay.** More sophisticated attacks capture NetNTLM challenge/response hashes from SMB authentication attempts and relay or crack them offline.

## Further reading

- [How Metasploit is detected](../05-detection/how-metasploit-is-detected.md)
- [Services explained](../03-code-walkthrough/services-explained.md)
- [Defense in depth](../01-concepts/defense-in-depth.md)
