# Legal Framework

Operating a honeypot involves legal considerations that vary by jurisdiction. This document covers the primary legal issues: authorization to operate the honeypot, liability for attacker activity, data protection obligations, and the legality of acting on captured intelligence.

**This document is not legal advice.** Consult a qualified attorney familiar with the laws of your jurisdiction before deploying trapnet in any production context.

## Authorization

The most important legal question is: do you have authorization to operate the honeypot on this network?

**On your own infrastructure.** If you own or control the IP address and the host, you are generally authorized to operate a honeypot. The honeypot accepts connections that are directed at your IP. There is no legal issue with logging what strangers send to your own address.

**On employer infrastructure.** Deploying a honeypot on a network you do not own requires explicit authorization from the network owner. This should be in writing. Many security professionals have been disciplined or terminated for running unauthorized network tools, even defensive ones.

**On cloud infrastructure.** Most cloud providers' terms of service permit security monitoring tools. Review your provider's acceptable use policy. Some providers require disclosure when you observe active exploitation that may affect other customers.

## Entrapment concerns

Honeypots sometimes raise entrapment concerns. In most legal systems, entrapment applies only to law enforcement inducing someone to commit a crime they would not otherwise commit. A passive honeypot that simply listens for connections is not entrapment; the attacker chose to connect to your IP.

However, an active honeypot that solicits attacks, advertises false vulnerabilities in ways that recruit attackers who would not otherwise target you, or directs specific individuals toward your system may create legal complications. trapnet is fully passive.

## Computer fraud and abuse laws

Laws like the US Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in other jurisdictions criminalize unauthorized access to computer systems. Attackers connecting to trapnet are committing the offense, not you. However:

- Using captured attacker data to "hack back" against the attacker's infrastructure would itself be unauthorized access.
- Sharing captured exploit payloads publicly may violate laws against distribution of hacking tools in some jurisdictions.
- Retaining captured credentials is legal for investigation purposes but may be subject to data protection law obligations.

## Data protection obligations

EU GDPR, UK GDPR, and similar laws treat IP addresses as personally identifiable information. If you are subject to these laws:

- You may need a lawful basis for collecting and retaining IP addresses (e.g., legitimate interest in network security).
- You should have a retention policy and delete logs after the retention period.
- You may need to document your honeypot as a data processing activity.

GDPR's legitimate interest basis typically covers security monitoring, but the specifics depend on your organization's circumstances.

## Reporting to law enforcement

Honeypot data can be reported to law enforcement if it shows significant criminal activity. In practice, law enforcement rarely pursues individual honeypot incidents unless they are part of a larger investigation. If you observe a sustained targeted attack, a zero-day exploitation campaign, or activity connected to known criminal infrastructure, consider:

- Preserving logs with full chain of custody documentation
- Contacting your national CERT or CSIRT
- Contacting law enforcement through appropriate channels (FBI IC3 in the US, Action Fraud in the UK, etc.)

Do not contact the attacker, interfere with their systems, or attempt to identify them through means that would themselves be illegal.

## Summary

| Action | Generally legal |
|--------|----------------|
| Operating a honeypot on your own infrastructure | Yes |
| Logging connections and payloads | Yes |
| Sharing anonymized intelligence with threat feeds | Yes |
| Sharing full logs with law enforcement | Yes |
| Hacking back against the attacker | No |
| Publishing captured credentials | No |

## Further reading

- [Responsible disclosure](responsible-disclosure.md)
- [Logging and forensics](logging-and-forensics.md)
- [Network isolation best practices](network-isolation-best-practices.md)
