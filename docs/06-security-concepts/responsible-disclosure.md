# Responsible Disclosure

Responsible disclosure is the practice of notifying software or service vendors of security vulnerabilities before publishing them publicly, giving the vendor time to develop and release a fix. This document explains responsible disclosure in the context of operating a honeypot and what obligations arise from the data you collect.

## Why this is relevant to honeypot operators

Running trapnet will capture credential attempts, scanner activity, and sometimes payload data that reveals active exploitation of vulnerabilities in real software. You may observe:

- Credentials that appear to be valid account credentials from an ongoing breach
- Exploit payloads targeting CVEs in production software
- Attack infrastructure (C2 domains, payload hosting URLs) embedded in attacker payloads
- Evidence of active exploitation campaigns before public disclosure

Each of these creates a potential disclosure obligation.

## Observing an active exploitation campaign

If your honeypot captures payload data that suggests a previously unknown vulnerability is being actively exploited (a zero-day), responsible disclosure involves:

1. **Preserve the evidence.** Save the raw log entries and payload bytes. Do not alter them.
2. **Analyze safely.** Do not execute any captured payloads. Analyze in an isolated environment.
3. **Identify the affected vendor.** Determine which software the payload targets.
4. **Contact the vendor's security team.** Most vendors publish a security contact address or a bug bounty program. Use these channels.
5. **Set a disclosure timeline.** Industry standard is 90 days from vendor notification before public disclosure, regardless of whether the vendor has released a fix. Google Project Zero popularized this timeline.

## Credentials from ongoing breaches

If you observe credentials that appear to be from a credential stuffing campaign against a specific service (e.g., email addresses and passwords clearly targeting one company), consider notifying that company's security team. They can force password resets for affected accounts.

Do not use the credentials yourself for any purpose. Do not publish them. Do not retain them longer than necessary for reporting.

## Attack infrastructure data

If attacker payloads contain URLs, domain names, or IP addresses used for malware hosting or command-and-control, this information can be shared with:

- **MISP instances or threat sharing platforms** (CIRCL, ISACs)
- **The hosting provider** via their abuse contact (found in WHOIS or via abuse@[provider])
- **Domain registrars** for malicious domains
- **Law enforcement** if you have evidence of significant criminal activity

## What responsible disclosure is not

Responsible disclosure does not mean:

- Publishing vulnerability details before a fix is available without vendor notification
- Demanding payment or reward in exchange for not publishing (this is extortion)
- Sharing captured credentials publicly in any form
- Retaliating against attackers using captured infrastructure

## trapnet and third-party data

trapnet captures data about third parties: the attackers themselves. Depending on your jurisdiction, storing IP addresses and credentials may be subject to data protection laws. Review the legal framework document for the jurisdictional implications.

## Further reading

- [Legal framework](legal-framework.md)
- [IOC and threat intel](ioc-and-threat-intel.md)
- [Logging and forensics](logging-and-forensics.md)
