# dashboard-explained.md

`trapnet/dashboard/app.py` is a Flask web application that provides a browser-based view of captured connection data.

## Current state

The dashboard is currently a stub. The two routes it exposes are:

- `GET /` -- returns a simple HTML placeholder page
- `GET /api/stats` -- returns `{"status": "ok"}`

Full dashboard functionality (connection table, charts, scanner breakdown, export) is planned for a future release. The architecture is in place: the Flask app receives the `logger` and `config` objects at creation time and can use them to query the database.

## How it runs

The dashboard runs in a `threading.Thread` (daemon thread), launched from `__main__.py`. It does not share the asyncio event loop. Flask uses its own WSGI server (Werkzeug's built-in server) to handle HTTP requests from a browser.

Because it runs in a separate thread, it cannot call `async` functions directly. It accesses data by querying SQLite synchronously. SQLite's write-ahead logging mode (or default journal mode) handles concurrent access between the Flask thread and the logger's async writes without locking conflicts.

## Security defaults

The dashboard binds to `127.0.0.1` by default. This means it is only accessible from the machine running trapnet. To expose it on a network interface, change `dashboard.host` in `config.yml` -- but only after adding authentication, since it displays raw attacker payloads and captured credentials.

The `config.dashboard.password` field exists for a future HTTP basic auth guard on all routes. The default value is `"changeme"`, which must be changed before exposing the dashboard to any network.

## Planned routes

When fully implemented, the dashboard will include:

- `GET /` -- connection table with filtering by IP, service, date
- `GET /api/stats` -- JSON stats for chart rendering
- `GET /api/connections` -- paginated connection list
- `GET /export/json` -- full database export as JSON
- `GET /export/csv` -- full database export as CSV

## Further reading

- [logger.py explained](logger-explained.md)
- [Security implications of architecture](../02-architecture/security-implications-of-architecture.md)
