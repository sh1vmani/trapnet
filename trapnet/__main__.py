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
    # Wraps the core logger module so handlers receive an object with a simple
    # log_connection(conn_data) method rather than calling module functions directly.
    def __init__(self, db_path: str, json_path: str) -> None:
        self.db_path = db_path
        self.json_path = json_path

    async def log_connection(self, conn_data: dict) -> None:
        await core_logger.log_connection(self.db_path, self.json_path, conn_data)

    async def get_recent(self, limit: int = 100) -> list:
        return await core_logger.get_recent(self.db_path, limit)

    async def get_stats(self) -> dict:
        return await core_logger.get_stats(self.db_path)


def _check_legal() -> None:
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
        try:
            await engine.start()
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
