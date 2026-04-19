# Defense in Depth

Defense in depth is the practice of layering multiple independent security controls so that the failure of any single control does not compromise the whole system. A honeypot is one layer in this strategy, not a replacement for the others.

## The layered model

A typical defense-in-depth stack, from the network edge inward:

1. **Perimeter firewall** - blocks traffic that has no business reason to reach your network.
2. **Network segmentation** - limits lateral movement if the perimeter is breached.
3. **Intrusion detection system (IDS)** - inspects traffic that passes the firewall for known attack patterns.
4. **Host hardening** - removes unnecessary services, patches known vulnerabilities, enforces least privilege.
5. **Application security** - authentication, authorization, input validation, and output encoding in every application.
6. **Logging and monitoring** - records what happened so you can detect, investigate, and respond.
7. **Honeypots** - attract and log attacker activity, providing early warning and threat intelligence.

## Where honeypots fit

A honeypot does not stop attacks. It observes them. Its value is in the intelligence it produces and the early warning it provides when something is probing your network.

Placing a honeypot inside your network (behind the perimeter firewall) means that any connection to it represents a threat that has already bypassed the outer layer. That is a high-signal alert.

Placing a honeypot on a publicly routable IP (in a DMZ or on a cloud host) captures internet-wide scanning activity. This is useful for threat intelligence but the signal-to-noise ratio is much higher.

## trapnet's role

trapnet is a passive sensor. It does not:

- Block traffic
- Alert in real time (there is no notification system)
- Patch vulnerabilities
- Prevent data exfiltration

It does:

- Record every connection attempt with full payload and GeoIP context
- Identify which tools and techniques are being used against your network
- Capture credentials being tested in stuffing attacks
- Provide a historical log for forensic analysis

Pair trapnet with a firewall, an IDS, and a SIEM to get the full benefit of the intelligence it generates.

## Isolation

A honeypot should not have network access to your production systems. If an attacker somehow exploits the honeypot process itself (unlikely for a low-interaction honeypot with no real services, but possible), you do not want them to have a stepping stone into your infrastructure.

Run trapnet in a dedicated VM or container on an isolated network segment. The `config.yml` dashboard should bind to `127.0.0.1` unless you have a specific reason to expose it.

## Further reading

- [Network isolation best practices](../06-security-concepts/network-isolation-best-practices.md)
- [Least privilege explained](../06-security-concepts/least-privilege-explained.md)
