# Network Isolation Best Practices

Network isolation is the practice of segmenting systems so that a compromise in one segment cannot easily spread to others. For a honeypot, isolation serves two purposes: it limits what an attacker can reach if they exploit the honeypot, and it prevents the honeypot from being used as a pivot point into the real network.

## The honeypot isolation model

A properly isolated honeypot should be on a network segment with the following properties:

**No route to production systems.** The honeypot's network interface should have no path to any host that holds real data or serves real users. A dedicated VLAN, a separate physical interface, or a cloud VPC with no peering to production VPCs achieves this.

**Outbound restrictions.** The honeypot should not be able to make arbitrary outbound connections. Permitted outbound traffic:
- DNS queries to a resolver (needed for GeoIP hostname lookups)
- NTP to a time server (for accurate timestamps)
- Log shipping to a remote syslog or SIEM (one-way, if implemented)

All other outbound connections should be blocked. This prevents an attacker who compromises the honeypot process from using it to attack other hosts.

**Inbound restrictions.** The only inbound traffic the honeypot should accept is:
- TCP connections to the ports trapnet listens on (from any source IP)
- SSH from a specific administrator IP range (for management)

Everything else should be blocked.

## Firewall rules example (iptables)

```bash
# Allow established outbound connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from management IPs only
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT

# Allow trapnet honeypot ports from anywhere
iptables -A INPUT -p tcp -m multiport --dports 21,22,23,25,80,110,443,1433,3306,3389,5432,5900,6379,27017,11211 -j ACCEPT

# Block all other inbound
iptables -A INPUT -j DROP

# Allow DNS and NTP outbound
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# Allow log shipping outbound (example: syslog to 10.0.1.100)
iptables -A OUTPUT -p tcp --dport 514 -d 10.0.1.100 -j ACCEPT

# Block all other outbound
iptables -A OUTPUT -j DROP
```

These rules ensure the honeypot accepts connections on its monitored ports but cannot initiate connections to other systems.

## Cloud deployment isolation

In AWS, GCP, or Azure:

- Deploy the honeypot in a dedicated VPC with no VPC peering to production environments.
- Use a security group that allows inbound on honeypot ports from `0.0.0.0/0` and SSH from your management CIDR.
- Set the outbound security group to allow only DNS (UDP 53), NTP (UDP 123), and log shipping.
- Do not assign an IAM role with any permissions to the honeypot instance. If it is compromised, the attacker should not be able to call cloud APIs.

## Why outbound blocking matters

An attacker who gains code execution within the trapnet process has access to the network. Without outbound blocking, they could:

- Port-scan other hosts on the same network
- Exfiltrate data to external servers
- Download additional malware
- Use the honeypot as a relay for attacks on other targets

Outbound blocking converts a potential pivot point into a dead end. The attacker's code runs but cannot reach anything useful.

## Monitoring the isolation

Log all blocked outbound connections. An unexpected outbound connection attempt from the honeypot host is a high-confidence indicator that the honeypot process has been compromised. This is one of the few cases where honeypot intrusion is detectable in real time.

## Further reading

- [Least privilege explained](least-privilege-explained.md)
- [Legal framework](legal-framework.md)
- [Security implications of architecture](../02-architecture/security-implications-of-architecture.md)
