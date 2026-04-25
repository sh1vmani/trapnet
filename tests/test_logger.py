import json
import pytest
import aiosqlite
from trapnet.core.logger import (
    init_db, log_connection, get_recent, get_stats, export_json, export_csv,
)

_CONN = {
    "timestamp": "2026-01-01T00:00:00+00:00",
    "src_ip": "1.2.3.4",
    "src_port": 12345,
    "dst_port": 22,
    "service": "ssh",
    "payload": "deadbeef",
    "scanner_type": "NMAP",
}


@pytest.mark.asyncio
async def test_init_db(tmp_path):
    db = str(tmp_path / "test.db")
    await init_db(db)
    async with aiosqlite.connect(db) as conn:
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='connections'"
        ) as cur:
            row = await cur.fetchone()
    assert row is not None


@pytest.mark.asyncio
async def test_log_and_retrieve(tmp_path):
    db = str(tmp_path / "test.db")
    jpath = str(tmp_path / "test.json")
    await init_db(db)
    await log_connection(db, jpath, _CONN)
    rows = await get_recent(db, limit=10)
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "1.2.3.4"
    assert rows[0]["service"] == "ssh"
    assert rows[0]["scanner_type"] == "NMAP"


@pytest.mark.asyncio
async def test_get_stats_empty(tmp_path):
    db = str(tmp_path / "test.db")
    await init_db(db)
    stats = await get_stats(db)
    assert stats["total_connections"] == 0


@pytest.mark.asyncio
async def test_export_json(tmp_path):
    db = str(tmp_path / "test.db")
    jpath = str(tmp_path / "test.json")
    export_path = str(tmp_path / "export.json")
    await init_db(db)
    await log_connection(db, jpath, _CONN)
    await export_json(db, export_path)
    with open(export_path) as f:
        data = json.load(f)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["src_ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_export_csv(tmp_path):
    db = str(tmp_path / "test.db")
    jpath = str(tmp_path / "test.json")
    csv_path = str(tmp_path / "export.csv")
    await init_db(db)
    await log_connection(db, jpath, _CONN)
    await export_csv(db, csv_path)
    with open(csv_path) as f:
        lines = f.readlines()
    assert len(lines) >= 2
    assert "src_ip" in lines[0]
