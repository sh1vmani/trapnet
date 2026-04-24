# Least Privilege Explained

Least privilege is the principle that a process, user, or service should have only the permissions it needs to do its job, and no more. It is one of the foundational concepts in defensive security. For a honeypot like trapnet, applying least privilege correctly limits what an attacker can do if they somehow compromise the process.

## Why least privilege matters for a honeypot

A honeypot is deliberately exposed to hostile traffic. If the honeypot process has broad permissions and a vulnerability is found in it, an attacker who exploits that vulnerability inherits all of the process's permissions. If the process runs as root with full filesystem access, so does the attacker.

trapnet's threat model includes the possibility that a bug in a service handler allows a remote attacker to execute code within the trapnet process. Least privilege limits the damage in that scenario.

## What trapnet needs

trapnet's legitimate requirements are:

- Listen on TCP ports below 1024 (which requires elevated privileges on Linux)
- Write log files to a designated directory
- Read its configuration file
- Make DNS lookups for GeoIP resolution

That is all. trapnet does not need:

- Read or write access to any other filesystem paths
- Network access to other hosts in the same network
- The ability to spawn child processes
- Root privileges at runtime (only for initial bind)

## How to apply least privilege to trapnet

**Run as a dedicated user.** Create a system user (`trapnet` or `honeypot`) with no login shell and no home directory. The process runs under this user identity after startup. The user owns only the log directory and config file.

**Use Linux capabilities instead of root.** Binding to ports below 1024 requires the `CAP_NET_BIND_SERVICE` capability. Instead of running the entire process as root, grant just this one capability to the Python binary or use a tool like `setcap`. After binding, the process drops to the unprivileged user.

**Restrict filesystem access.** Use a systemd service unit with `ProtectSystem=strict` and `ReadWritePaths=` limited to the log directory. This prevents the process from writing anywhere else on the filesystem even if exploited.

**Apply network filtering.** Use iptables or nftables rules to prevent the trapnet process from making outbound connections except for DNS. A honeypot process should not be able to be turned into an outbound attack platform.

## Principle of least privilege beyond trapnet

The same principle applies to everything in the system:

- The log directory should be writable by trapnet and readable by only the user running log analysis tools.
- SSH access to the honeypot host should be limited to specific administrator IPs.
- The host running trapnet should not be on the same network segment as production systems.

Defense in depth is least privilege applied at multiple layers. Each layer independently limits what an attacker can reach.

## The systemd example

A minimal systemd unit applying least privilege:

```ini
[Service]
User=trapnet
Group=trapnet
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ReadWritePaths=/var/log/trapnet
PrivateTmp=true
NoNewPrivileges=true
```

`NoNewPrivileges=true` prevents the process from gaining additional capabilities through setuid binaries. `PrivateTmp=true` gives it an isolated `/tmp`. `ProtectSystem=strict` makes the entire filesystem read-only except where explicitly allowed.

## Further reading

- [Network isolation best practices](network-isolation-best-practices.md)
- [Legal framework](legal-framework.md)
- [Security implications of architecture](../02-architecture/security-implications-of-architecture.md)
