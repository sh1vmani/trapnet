from __future__ import annotations
import asyncio
from trapnet.core import services as svc_module


SERVICE_HANDLERS = {
    "ssh":        svc_module.handle_ssh,
    "ftp":        svc_module.handle_ftp,
    "telnet":     svc_module.handle_telnet,
    "http":       svc_module.handle_http,
    "https":      svc_module.handle_https,
    "mysql":      svc_module.handle_mysql,
    "postgresql": svc_module.handle_postgresql,
    "redis":      svc_module.handle_redis,
    "mongodb":    svc_module.handle_mongodb,
    "smb":        svc_module.handle_smb,
    "rdp":        svc_module.handle_rdp,
    "smtp":       svc_module.handle_smtp,
    "pop3":       svc_module.handle_pop3,
    "vnc":        svc_module.handle_vnc,
    "memcached":  svc_module.handle_memcached,
}


class _EnrichedLogger:
    # Wraps the logger to inject GeoIP data at log time, not at connection-open
    # time, so GeoIP rate limiting never delays the start of a handler.
    def __init__(self, logger, geoip, src_ip: str) -> None:
        self._logger = logger
        self._geoip = geoip
        self._src_ip = src_ip

    async def log_connection(self, conn_data: dict) -> None:
        geo = await self._geoip.lookup(self._src_ip)
        conn_data.setdefault("country", geo.get("country"))
        conn_data.setdefault("city", geo.get("city"))
        await self._logger.log_connection(conn_data)


class HoneypotEngine:
    """Starts and manages one asyncio server per enabled service."""

    def __init__(self, config, logger, detector, geoip) -> None:
        self._config = config
        self._logger = logger
        self._detector = detector
        self._geoip = geoip
        self._servers: list[asyncio.AbstractServer] = []

    def _make_handler(self, handler_fn):
        # Closure captures engine state so asyncio.start_server receives a plain callable
        async def _handler(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            src_ip = writer.get_extra_info("peername")[0]
            enriched = _EnrichedLogger(self._logger, self._geoip, src_ip)
            await handler_fn(reader, writer, enriched, self._detector, self._config)
        return _handler

    async def start(self) -> None:
        """Bind all enabled services and serve until cancelled."""
        for name, svc in self._config.services.items():
            if not svc.enabled:
                continue
            handler_fn = SERVICE_HANDLERS.get(name)
            if handler_fn is None:
                print(f"warning: no handler registered for service {name!r}, skipping")
                continue
            try:
                server = await asyncio.start_server(
                    self._make_handler(handler_fn),
                    host="0.0.0.0",
                    port=svc.port,
                )
            except OSError as exc:
                print(f"warning: could not bind {name} on port {svc.port}: {exc}")
                continue
            self._servers.append(server)
            print(f"listening: {name} on port {svc.port}")

        active = len(self._servers)
        dash = self._config.dashboard
        print()
        print("trapnet v0.1.0 started")
        print(f"{active} services active")
        print(f"dashboard: http://{dash.host}:{dash.port}")
        print("press Ctrl+C to stop")
        print()

        await asyncio.gather(*(s.serve_forever() for s in self._servers))

    async def stop(self) -> None:
        """Close all bound servers and wait for them to finish."""
        for server in self._servers:
            server.close()
        await asyncio.gather(*(s.wait_closed() for s in self._servers))
        print("trapnet stopped cleanly")
