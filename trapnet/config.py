from __future__ import annotations
import os
from dataclasses import dataclass, field
import yaml


@dataclass
class ServiceConfig:
    enabled: bool = True
    port: int = 0


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    password: str = "changeme"
    enabled: bool = True


@dataclass
class LoggingConfig:
    sqlite_path: str = "logs/trapnet.db"
    json_log_path: str = "logs/trapnet.json"
    max_log_size_mb: int = 100


@dataclass
class DetectionConfig:
    enabled: bool = True
    alert_threshold: int = 3


@dataclass
class SnortConfig:
    enabled: bool = False
    alert_file: str = "/var/log/snort/alert"


@dataclass
class Config:
    services: dict = field(default_factory=dict)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    snort: SnortConfig = field(default_factory=SnortConfig)

    @classmethod
    def load(cls, path: str) -> "Config":
        # Fail early with a clear message rather than a cryptic FileNotFoundError
        if not os.path.isfile(path):
            raise ValueError(
                f"Config file not found: {path!r}. "
                "Create one or copy the default config.yml from the repo root."
            )
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        return cls._parse(raw or {})

    @classmethod
    def load_default(cls) -> "Config":
        # Returns a fully populated config using built-in defaults, no file needed
        return cls._parse({})

    @classmethod
    def _parse(cls, raw: dict) -> "Config":
        # Parse services block - each key maps to enabled + port
        services = {}
        for name, svc in raw.get("services", {}).items():
            if not isinstance(svc, dict):
                raise ValueError(f"services.{name} must be a mapping, got {type(svc).__name__}")
            port = svc.get("port", 0)
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"services.{name}.port must be 1-65535, got {port!r}")
            services[name] = ServiceConfig(
                enabled=bool(svc.get("enabled", True)),
                port=port,
            )

        # Parse dashboard block
        db_raw = raw.get("dashboard", {})
        dashboard = DashboardConfig(
            host=db_raw.get("host", "127.0.0.1"),
            port=int(db_raw.get("port", 5000)),
            password=db_raw.get("password", "changeme"),
            enabled=bool(db_raw.get("enabled", True)),
        )

        # Parse logging block
        log_raw = raw.get("logging", {})
        logging_cfg = LoggingConfig(
            sqlite_path=log_raw.get("sqlite_path", "logs/trapnet.db"),
            json_log_path=log_raw.get("json_log_path", "logs/trapnet.json"),
            max_log_size_mb=int(log_raw.get("max_log_size_mb", 100)),
        )

        # Parse detection block
        det_raw = raw.get("detection", {})
        detection = DetectionConfig(
            enabled=bool(det_raw.get("enabled", True)),
            alert_threshold=int(det_raw.get("alert_threshold", 3)),
        )

        # Parse snort integration block
        snort_raw = raw.get("snort", {})
        snort = SnortConfig(
            enabled=bool(snort_raw.get("enabled", False)),
            alert_file=snort_raw.get("alert_file", "/var/log/snort/alert"),
        )

        return cls(
            services=services,
            dashboard=dashboard,
            logging=logging_cfg,
            detection=detection,
            snort=snort,
        )
