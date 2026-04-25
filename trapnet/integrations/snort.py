from __future__ import annotations
import asyncio
import re
from datetime import datetime, timezone


# Snort fast alert format:
#   [**] [gid:sid:rev] Alert message [**]
#   [Priority: N]
#   MM/DD-HH:MM:SS.ffffff src_ip:src_port -> dst_ip:dst_port

_ADDR_LINE = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"   # timestamp
    r"\s+([\d.]+)(?::\d+)?"                     # src_ip (port optional)
    r"\s+->\s+"
    r"([\d.]+):(\d+)"                           # dst_ip:dst_port
)

_MSG_LINE = re.compile(r"\[\*\*\]\s+\[[\d:]+\]\s+(.+?)\s+\[\*\*\]")


class SnortTailer:
    """Tails a Snort fast-alert file and logs each alert as a connection record."""

    def __init__(self, alert_file: str, logger, db_path: str, json_path: str) -> None:
        self._alert_file = alert_file
        self._logger = logger
        self._db_path = db_path
        self._json_path = json_path
        self._running = False

    async def start(self) -> None:
        """Seek to the end of the alert file and tail it until stopped."""
        self._running = True
        try:
            with open(self._alert_file, "r") as fh:
                fh.seek(0, 2)  # seek to end: tail behavior, skip existing alerts
                pending: list[str] = []
                while self._running:
                    line = fh.readline()
                    if line:
                        pending.append(line.rstrip("\n"))
                        # Snort fast alert blocks are separated by blank lines
                        if line.strip() == "" and pending:
                            await self._handle_block(pending)
                            pending = []
                    else:
                        await asyncio.sleep(2)
                if pending:
                    await self._handle_block(pending)
        except FileNotFoundError:
            print(f"snort alert file not found: {self._alert_file!r}")
        except Exception as exc:
            print(f"snort tailer error: {exc}")

    async def stop(self) -> None:
        """Signal the tailing loop to exit after the current iteration."""
        self._running = False

    async def _handle_block(self, lines: list[str]) -> None:
        try:
            msg = None
            src_ip = None
            dst_port = None

            for line in lines:
                m = _MSG_LINE.match(line)
                if m:
                    msg = m.group(1)
                    continue
                m = _ADDR_LINE.search(line)
                if m:
                    src_ip = m.group(2)
                    dst_port = int(m.group(4))

            if src_ip is None:
                # Block did not contain a parseable address line: log raw text.
                # 0.0.0.0 is used instead of a string sentinel because the GeoIP
                # is_private() check expects a valid IP address.
                raw = " | ".join(lines)
                src_ip = "0.0.0.0"
                dst_port = 0
                msg = msg or raw

            await self._logger.log_connection({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": src_ip,
                "src_port": None,
                "dst_port": dst_port,
                "service": "snort",
                "payload": msg or "",
                "scanner_type": "SNORT_ALERT",
            })
        except Exception as exc:
            print(f"snort block parse error: {exc}")
