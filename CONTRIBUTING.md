# Contributing to trapnet

Thanks for your interest. This document covers how to set up a development environment, the conventions used in this project, and what kinds of contributions are welcome.

## Development setup

```bash
git clone https://github.com/sh1vmani/trapnet.git
cd trapnet
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Python 3.10 or newer is required.

## Running the honeypot locally

Low-numbered ports (< 1024) require elevated privileges on Linux. For development, edit `config.yml` to use high-numbered ports:

```yaml
services:
  ssh:
    enabled: true
    port: 2222
  http:
    enabled: true
    port: 8080
```

Then run:

```bash
python -m trapnet --config config.yml
```

## Code style

- Follow PEP 8. Line length limit is 100 characters.
- All I/O that can block must use `async`/`await`.
- No new third-party dependencies without discussion in a GitHub issue first.
- Comments only when the reason is non-obvious. Never comment what the code does.

## Adding a new service emulator

1. Write an `async def handle_<name>(reader, writer, logger, detector, config)` function in `trapnet/core/services.py`.
2. Register it in `SERVICE_HANDLERS` in `trapnet/core/engine.py`.
3. Add a default port entry in `config.yml` and document it in `docs/04-protocols/`.
4. Add the service name to the auth_services set in `detector.py` if it carries credentials.

## Submitting a pull request

- Open an issue first for non-trivial changes so we can agree on the approach.
- One logical change per PR.
- Include a short description of what the change does and why.
- Do not commit `.trapnet_accepted`, `logs/`, or any secrets.

## Reporting bugs

Use the GitHub issue tracker. Include the OS, Python version, and the full traceback if applicable.
