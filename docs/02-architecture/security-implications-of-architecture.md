# Security Implications of Architecture

trapnet's architecture was designed with specific security properties in mind. This document explains those choices and their limits.

## No real services run

trapnet does not run real SSH, MySQL, or any other service software. It only speaks enough of each protocol to convince a scanner that a service is present. There is no shell, no database, no file system accessible through any of the emulated services. An attacker who receives a login failure cannot escalate, pivot, or extract data through the honeypot.

This is the most important security property of a low-interaction honeypot. The attack surface is the protocol handler code itself, not the emulated service.

## Minimal process privileges

trapnet does not need to run as root. Listening on ports below 1024 requires elevated privileges on Linux. The recommended approach is to either:

- use `authbind` or `setcap cap_net_bind_service` on the Python binary
- run behind a port-forward rule (e.g., `iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222`)

Running as a non-root user limits the blast radius if a vulnerability in the handler code is ever exploited.

## Handler isolation

Each protocol handler is a plain async function. A bug in `handle_ssh()` cannot directly affect `handle_ftp()`. If a handler raises an unhandled exception, asyncio logs the traceback and closes that connection without crashing the engine.

However, all handlers share the same process. A memory-corruption exploit or a Python escape from the sandbox (e.g., via a maliciously crafted pickle payload, if one were ever deserialized) would have full process access. Handlers should never deserialize untrusted input with pickle, eval, or similar.

## Dashboard is localhost-only by default

`config.yml` defaults `dashboard.host` to `127.0.0.1`. The dashboard should not be exposed to the internet: it shows raw attacker payloads and credentials. If remote access is needed, put it behind a VPN or an authenticated reverse proxy (e.g., nginx with HTTP basic auth).

## GeoIP is an outbound connection

trapnet makes outbound HTTP requests to ip-api.com for GeoIP enrichment. On a hardened deployment, this may require a firewall exception. More importantly, ip-api.com will see your honeypot's source IP and query patterns. If operational security requires that the honeypot's network location be concealed, disable GeoIP enrichment or route it through a proxy.

## Log files contain sensitive data

The SQLite database and JSON log file contain raw attacker payloads, which may include credential strings from real production systems that attackers are cycling. Restrict read access to these files to the user running trapnet. Do not ship them to a shared logging system without redacting or encrypting credential fields.

## No active response capability

trapnet does not block IPs, send alerts, or update firewall rules. It is a passive sensor. This is a deliberate design choice: active response from a honeypot can cause collateral damage if the source IP is spoofed or shared (e.g., a NAT gateway), and it can tip off an attacker that they have been detected. Blocking and alerting should be handled by a separate system that consumes trapnet's logs.

## Further reading

- [Legal framework](../06-security-concepts/legal-framework.md)
- [Network isolation best practices](../06-security-concepts/network-isolation-best-practices.md)
- [Logging and forensics](../06-security-concepts/logging-and-forensics.md)
