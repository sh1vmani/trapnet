# What Is a Honeypot?

A honeypot is a decoy system deployed alongside real infrastructure. It has no legitimate users and serves no production purpose, so any connection to it is inherently suspicious. Every packet that arrives is either a scanner, a bot, an attacker, or a misconfigured client.

## Why deploy one?

**Threat visibility.** Honeypots give you data on attack activity that your production logs never capture. A firewall drops the probe silently; a honeypot records the payload, the source IP, the timing, and the tool signature.

**Early warning.** A scanner that hits your honeypot is likely probing adjacent real hosts too. The honeypot event arrives before the attacker reaches anything of value.

**Threat intelligence.** Aggregating honeypot logs over time reveals which vulnerabilities are being mass-exploited right now, which credential lists are in circulation, and which scanner tools are most common in your threat environment.

## Types of honeypots

**Low-interaction honeypots** (like trapnet) emulate the network surface of a service without running the real software. They respond with realistic banners and protocol exchanges but never grant access. They are safe to operate, easy to deploy, and sufficient for capturing reconnaissance and credential stuffing activity.

**High-interaction honeypots** run real services in isolated environments. They capture more attacker behavior post-exploitation but carry more operational risk and complexity.

**Honeynets** are full networks of honeypot systems, used for large-scale threat research.

## What trapnet emulates

trapnet listens on 15 ports and responds with protocol-accurate banners and handshakes for SSH, FTP, Telnet, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB, SMB, RDP, SMTP, POP3, VNC, and Memcached. It captures credentials where the protocol involves an authentication exchange, logs every raw payload, and fingerprints the tool that sent it.

## Limitations

A low-interaction honeypot cannot capture post-exploitation behavior. An attacker who receives a login failure will not run commands, drop files, or move laterally through the emulated service. For that level of visibility, a high-interaction honeypot or a canary token system is more appropriate.

trapnet is also not a prevention tool. It does not block attackers, alert in real time, or integrate with a firewall. It is a passive logging and intelligence-gathering instrument.

## Further reading

- [How attackers scan networks](how-attackers-scan-networks.md)
- [Service emulation explained](service-emulation-explained.md)
- [Threat intelligence basics](threat-intelligence-basics.md)
