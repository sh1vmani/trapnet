from __future__ import annotations
import argparse
import asyncio
import os
import sys
import threading

from trapnet.config import Config
from trapnet.core import logger as core_logger
from trapnet.core import geoip
from trapnet.core.detector import AttackDetector
from trapnet.core.engine import HoneypotEngine
from trapnet.dashboard.app import create_app


ACCEPTED_FILE = ".trapnet_accepted"

LEGAL_TEXT = (
    "trapnet - Honeypot Framework\n"
    "\n"
    "Before continuing, confirm that you are authorized\n"
    "to monitor the network and systems where this tool\n"
    "will be deployed. Unauthorized use may violate\n"
    "local and federal law.\n"
    "\n"
)


class Logger:
    """Thin object wrapper around the core logger module.

    Handlers receive a Logger instance rather than calling module
    functions directly, which keeps their signatures stable if the
    underlying storage layer changes.
    """

    def __init__(self, db_path: str, json_path: str) -> None:
        self.db_path = db_path
        self.json_path = json_path

    async def log_connection(self, conn_data: dict) -> None:
        """Persist one connection record to SQLite and the JSON log."""
        await core_logger.log_connection(self.db_path, self.json_path, conn_data)

    async def get_recent(self, limit: int = 100) -> list:
        """Return the most recent connection records, newest first."""
        return await core_logger.get_recent(self.db_path, limit)

    async def get_stats(self) -> dict:
        """Return aggregate statistics for the dashboard."""
        return await core_logger.get_stats(self.db_path)

    async def export_json(self, path: str) -> None:
        """Export all records to path as a JSON array."""
        await core_logger.export_json(self.db_path, path)

    async def export_csv(self, path: str) -> None:
        """Export all records to path as CSV with a header row."""
        await core_logger.export_csv(self.db_path, path)


def _check_legal() -> None:
    """Display the legal acknowledgment prompt and exit if not accepted."""
    if os.path.isfile(ACCEPTED_FILE):
        return
    print(LEGAL_TEXT, end="")
    try:
        answer = input("Type 'yes' to confirm and continue: ")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if answer.strip().lower() != "yes":
        print("Exiting.")
        sys.exit(0)
    with open(ACCEPTED_FILE, "w") as f:
        f.write("accepted\n")


def main() -> None:
    """Entry point: parse args, start the dashboard thread, and run the engine."""
    # Legal acknowledgment runs before any other setup
    _check_legal()

    parser = argparse.ArgumentParser(description="trapnet honeypot framework")
    parser.add_argument(
        "--config",
        default="config.yml",
        help="path to YAML config file (default: config.yml)",
    )
    args = parser.parse_args()

    config = Config.load(args.config)

    os.makedirs("logs", exist_ok=True)

    logger = Logger(config.logging.sqlite_path, config.logging.json_log_path)
    detector = AttackDetector()

    # Dashboard runs in a daemon thread so it exits when the main process exits
    dash_app = create_app(logger, config)
    dash_thread = threading.Thread(
        target=lambda: dash_app.run(
            host=config.dashboard.host,
            port=config.dashboard.port,
            debug=False,
            use_reloader=False,
        ),
        daemon=True,
    )
    dash_thread.start()

    engine = HoneypotEngine(config, logger, detector, geoip)

    async def run() -> None:
        await core_logger.init_db(config.logging.sqlite_path)
        tasks = [engine.start()]
        if config.snort.enabled:
            from trapnet.integrations.snort import SnortTailer
            tailer = SnortTailer(
                config.snort.alert_file,
                logger,
                config.logging.sqlite_path,
                config.logging.json_log_path,
            )
            tasks.append(tailer.start())
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            pass
        finally:
            await engine.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
