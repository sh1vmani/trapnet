import asyncio
from types import SimpleNamespace
import pytest

from trapnet.core.services import handle_ssh, handle_ftp, SSH_BANNER


class MockWriter:
    def __init__(self):
        self._data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self._data += data

    async def drain(self) -> None:
        pass

    def get_extra_info(self, key, default=None):
        return ("1.2.3.4", 12345) if key == "peername" else default

    def close(self) -> None:
        self.closed = True


class MockLogger:
    def __init__(self):
        self.logged = []

    async def log_connection(self, conn_data: dict) -> None:
        self.logged.append(conn_data)


class MockDetector:
    async def analyze(self, src_ip, dst_port, payload, service):
        return {"scanner_type": None, "confidence": 0.0, "indicators": []}


@pytest.mark.asyncio
async def test_ssh_handler():
    reader = asyncio.StreamReader()
    reader.feed_eof()
    writer = MockWriter()
    logger = MockLogger()
    config = SimpleNamespace(services={"ssh": SimpleNamespace(port=22)})

    await handle_ssh(reader, writer, logger, MockDetector(), config)

    assert SSH_BANNER in writer._data
    assert writer.closed


@pytest.mark.asyncio
async def test_ftp_credential_capture():
    reader = asyncio.StreamReader()
    reader.feed_data(b"USER foo\r\nPASS bar\r\n")
    reader.feed_eof()
    writer = MockWriter()
    logger = MockLogger()
    config = SimpleNamespace(services={"ftp": SimpleNamespace(port=21)})

    await handle_ftp(reader, writer, logger, MockDetector(), config)

    assert logger.logged[0]["credentials"] == "foo:bar"


@pytest.mark.asyncio
async def test_timeout_handling(monkeypatch):
    import trapnet.core.services as svc_module
    monkeypatch.setattr(svc_module, "HANDLER_TIMEOUT", 0.05)

    reader = asyncio.StreamReader()  # no data, no EOF: triggers timeout
    writer = MockWriter()
    logger = MockLogger()
    config = SimpleNamespace(services={"ssh": SimpleNamespace(port=22)})

    await handle_ssh(reader, writer, logger, MockDetector(), config)

    assert writer.closed
    assert logger.logged[0]["payload"] == ""
