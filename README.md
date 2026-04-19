# trapnet

Async honeypot framework that emulates 15 network services, fingerprints scanners, and logs every connection attempt with GeoIP context.

> **Legal notice:** Only deploy trapnet on networks you own or have explicit written authorization to monitor. See [LEGAL.md](LEGAL.md).

---

## Features

- **15 service emulators** - SSH, FTP, Telnet, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB, SMB, RDP, SMTP, POP3, VNC, Memcached
- **Scanner fingerprinting** - identifies Nmap, Masscan, Metasploit, Shodan/Censys, and credential stuffers with confidence scores
- **GeoIP enrichment** - country and city for every source IP via ip-api.com (free tier, cached per session)
- **Dual logging** - SQLite database and newline-delimited JSON, written concurrently
- **Web dashboard** - live stats at `http://localhost:5000` (Flask, password-protected)
- **Snort integration** - optional: tail Snort alert log and correlate with honeypot events
- **Zero blocking** - all service handlers and I/O run on a single asyncio event loop

---

## Quick start

### From source

```bash
git clone https://github.com/sh1vmani/trapnet.git
cd trapnet
pip install -e .
```

Copy and edit the default config:

```bash
cp config.yml my-config.yml
# edit my-config.yml: change dashboard password, disable services you don't need
```

Run (requires root or cap_net_bind_service for ports < 1024):

```bash
sudo trapnet --config my-config.yml
```

The first run shows a legal acknowledgment prompt. Type `yes` to continue. The response is saved to `.trapnet_accepted` so you are not prompted again.

### Docker

```bash
docker compose up -d
```

See [Docker](#docker) below for details.

---

## Configuration

All settings live in `config.yml`. The file is YAML and is validated at startup.

```yaml
services:
  ssh:
    enabled: true
    port: 22         # change if another service already owns this port
  ftp:
    enabled: true
    port: 21
  # ... one block per service

dashboard:
  host: "127.0.0.1"  # bind to 0.0.0.0 to expose on the network
  port: 5000
  password: "changeme"  # CHANGE THIS before deploying

logging:
  sqlite_path: "logs/trapnet.db"
  json_log_path: "logs/trapnet.json"
  max_log_size_mb: 100

detection:
  enabled: true
  alert_threshold: 3  # events from one IP in the window before tagging as scanner

snort:
  enabled: false
  alert_file: "/var/log/snort/alert"
```

### Disabling a service

Set `enabled: false` under the service block. trapnet skips that handler entirely and does not bind the port.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                     asyncio loop                     │
│                                                      │
│  HoneypotEngine                                      │
│    per-service asyncio.start_server() listeners      │
│    │                                                 │
│    ├── service handler (services.py)                 │
│    │     sends realistic banner / handshake          │
│    │     reads client data                           │
│    │     closes connection                           │
│    │                                                 │
│    ├── AttackDetector (detector.py)                  │
│    │     per-IP event tracking (last 60 s)           │
│    │     payload signature matching                  │
│    │     returns scanner_type + confidence           │
│    │                                                 │
│    └── Logger (logger.py)                            │
│          writes to SQLite + JSON simultaneously      │
│          enriches record with GeoIP data             │
│                                                      │
│  Flask dashboard (daemon thread)                     │
│    /              - status page                      │
│    /api/stats     - JSON stats from SQLite           │
└──────────────────────────────────────────────────────┘
```

---

## Docker

`docker-compose.yml` maps all service ports and mounts a local `logs/` directory.

```bash
# Build and start
docker compose up -d

# Watch logs
docker compose logs -f

# Stop
docker compose down
```

The container runs as a non-root user (uid 1000). Ports below 1024 are exposed by Docker's network stack, so no special Linux capabilities are needed inside the container.

---

## Logged fields

Every connection attempt writes one record to SQLite and one JSON line:

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 UTC |
| `src_ip` | attacker IP |
| `src_port` | attacker port |
| `dst_port` | honeypot port hit |
| `service` | service name (ssh, ftp, ...) |
| `payload` | hex-encoded raw bytes received |
| `credentials` | username:password if captured |
| `scanner_type` | NMAP / MASSCAN / METASPLOIT / SHODAN / CREDENTIAL_STUFFER / GENERIC_SCANNER |
| `country` | GeoIP country |
| `city` | GeoIP city |

---

## Requirements

- Python 3.10+
- See `requirements.txt` for Python dependencies

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE) (to be added).
