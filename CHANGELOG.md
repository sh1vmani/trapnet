# Changelog

All notable changes to trapnet are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

## v0.1.1 - 2026-04-25

### Fixed

- Suppress expected Windows connection reset errors in service handlers. On Windows, clients
  that drop non-HTTP connections after receiving protocol banners (SMTP, FTP, SMB, etc.) now
  close silently without printing handler errors to the terminal.

## v0.1.0 - 2026-04-24

### Added

- Async honeypot engine built on `asyncio.start_server`
- 15 service emulators: SSH, FTP, Telnet, HTTP, HTTPS, MySQL, PostgreSQL, Redis, MongoDB, SMB, RDP, SMTP, POP3, VNC, Memcached
- Realistic protocol banners and handshakes for each service
- Credential capture for FTP, Telnet, SMTP, POP3
- Scanner fingerprinting: Nmap, Masscan, Metasploit, Shodan/Censys, generic scanner, credential stuffer
- Per-IP event tracker with a 5-minute sliding window for behavioral detection
- Confidence scores and indicator lists for each detection result
- Dual logging: async SQLite (`aiosqlite`) and newline-delimited JSON (`aiofiles`)
- GeoIP enrichment via ip-api.com free tier, with per-session in-memory cache and 1 req/s rate limit
- YAML configuration loader with strict validation
- Web dashboard stub (Flask) with `/api/stats` endpoint
- Legal acknowledgment prompt on first run, gated by `.trapnet_accepted` sentinel file
- Snort integration stub (`trapnet/integrations/snort.py`)
- Docker support: `Dockerfile` and `docker-compose.yml`
- Full documentation suite in `docs/` covering concepts, architecture, code walkthrough, protocols, detection, and security
