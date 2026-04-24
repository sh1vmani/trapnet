# How Metasploit Is Detected

Metasploit Framework is a penetration testing platform that automates the development and execution of exploits. When Metasploit probes a target, it sends distinctive payloads that differ from generic scanners. trapnet detects Metasploit with a confidence score of 0.9, the highest of any scanner type.

## Why Metasploit has the highest confidence

Metasploit's detection signals are specific protocol-level signatures derived from how Metasploit modules construct their initial probe packets. These signatures are unlikely to appear in any legitimate traffic or in generic scanners that do not embed Metasploit's protocol implementations.

## Signal 1: String identifiers in payload

```python
if b"msfconsole" in payload_lower or b"metasploit" in payload_lower:
    msf.append("metasploit string in payload")
```

Some Metasploit modules embed literal strings in their payloads for various reasons. When these strings appear, the attribution is unambiguous.

## Signal 2: EternalBlue SMB probe signature

```python
if service == "smb" and payload.startswith(b"\x00\x00\x00\x2f\xff\x53\x4d\x42"):
    msf.append("EternalBlue SMB probe signature")
```

The bytes `\xff\x53\x4d\x42` are the SMB1 magic bytes (`\xffSMB`). The full prefix `\x00\x00\x00\x2f\xff\x53\x4d\x42` matches the specific byte sequence that the Metasploit EternalBlue scanner module (`auxiliary/scanner/smb/smb_ms17_010`) sends when probing for CVE-2017-0144. An SMB2 server receiving an SMB1 probe with this prefix is being checked for the EternalBlue vulnerability.

## Signal 3: MS17-010 RDP probe pattern

```python
if service == "rdp" and len(payload) >= 6 and payload[5:6] == b"\xe0":
    msf.append("MS17-010 RDP probe pattern")
```

The byte `0xe0` at offset 5 in an RDP packet is the X.224 Connection Request code. Metasploit's RDP-related scanning modules construct Connection Requests with a specific structure. While `0xe0` itself is part of the legitimate RDP protocol, the specific payload pattern around it in Metasploit probes is distinctive enough to use as an indicator at the confidence level.

## What happens after the probe

Metasploit modules that scan first and exploit later will probe to confirm vulnerability before launching the actual exploit. A trapnet log showing a Metasploit EternalBlue probe means the attacker is checking whether this IP is worth launching the full exploit against. In a real network, this would be followed by the exploit on the actual SMB service if the probe suggests the host is vulnerable.

## Metasploit vs manual exploitation

The detection signals above are specific to Metasploit's automated modules. A skilled attacker who crafts packets manually will not trigger these signals unless they deliberately reproduce Metasploit's exact byte sequences. This means the METASPLOIT detection primarily catches automated tools and less experienced attackers using off-the-shelf frameworks.

## Confidence of 0.9

The 0.9 confidence is the highest because the signatures are specific. But it is not 1.0 because:

- A red team operator could deliberately modify Metasploit payloads to change the signature.
- Other tools that embed Metasploit's libraries would produce the same signatures.
- The RDP byte offset check is less specific than the SMB prefix check.

## Further reading

- [SMB protocol](../04-protocols/smb-protocol.md)
- [RDP protocol](../04-protocols/rdp-protocol.md)
- [Understanding confidence scores](understanding-confidence-scores.md)
- [Detector explained](../03-code-walkthrough/detector-explained.md)
