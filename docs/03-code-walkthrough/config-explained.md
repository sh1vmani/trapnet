# config.py Explained

`trapnet/config.py` is responsible for loading `config.yml` and validating it into typed dataclass objects that the rest of the application can use safely.

## Why dataclasses?

The config is passed into every major component. Using typed dataclasses instead of raw dicts means:

- a missing key is a clear `AttributeError`, not a silent `None`
- type checkers and IDEs can verify usage
- field names are enforced at parse time, so typos in `config.yml` fail early

## The dataclasses

```python
ServiceConfig   - enabled (bool), port (int)
DashboardConfig - host, port, password, enabled
LoggingConfig   - sqlite_path, json_log_path, max_log_size_mb
DetectionConfig - enabled, alert_threshold
SnortConfig     - enabled, alert_file
Config          - services (dict), dashboard, logging, detection, snort
```

`Config.services` is a dict from service name to `ServiceConfig`. The engine iterates this dict to decide which ports to open.

## Load paths

`Config.load(path)` reads a file. `Config.load_default()` uses built-in defaults with no file. Both delegate to `Config._parse(raw)`.

`load_default()` exists so tests and CI can run without a config file.

## Validation in _parse

The `_parse` classmethod validates every field before constructing the dataclasses:

- Service ports must be integers in the range 1-65535. A string like `"22"` or a value of `0` raises `ValueError`.
- Service entries must be dicts. A YAML list or scalar raises `ValueError`.
- All other fields coerce silently using `int()`, `bool()`, and `.get(key, default)`.

Validation happens at startup, not at the point of use, so a bad config is caught before any port is opened.

## What _parse does not validate

- Whether ports conflict with each other (two services on port 22 will fail when the second `asyncio.start_server()` call raises `OSError`).
- Whether the dashboard password is strong. The default `"changeme"` is allowed -- the operator is responsible for changing it.
- Whether paths in the logging config are writable. Logger creates directories on first write.

## Further reading

- [System overview](../02-architecture/system-overview.md)
- [engine.py explained](engine-explained.md)
