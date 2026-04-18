from __future__ import annotations
import json
import os
from datetime import datetime, timezone
import aiofiles
import aiosqlite


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    service TEXT NOT NULL,
    payload TEXT,
    credentials TEXT,
    scanner_type TEXT,
    country TEXT,
    city TEXT,
    raw_data BLOB
)
"""


async def init_db(db_path: str) -> None:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.execute(CREATE_TABLE_SQL)
        await db.commit()


async def log_connection(db_path: str, json_path: str, conn_data: dict) -> None:
    os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)

    # Parameterized query - never interpolate user-supplied values into SQL strings
    # to prevent injection even when the attacker controls the payload field
    sql = """
        INSERT INTO connections
            (timestamp, src_ip, src_port, dst_port, service,
             payload, credentials, scanner_type, country, city, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    row = (
        conn_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        conn_data.get("src_ip", ""),
        conn_data.get("src_port"),
        conn_data.get("dst_port"),
        conn_data.get("service", ""),
        conn_data.get("payload"),
        conn_data.get("credentials"),
        conn_data.get("scanner_type"),
        conn_data.get("country"),
        conn_data.get("city"),
        conn_data.get("raw_data"),
    )
    async with aiosqlite.connect(db_path) as db:
        await db.execute(sql, row)
        await db.commit()

    # Write the same record to the JSON log file simultaneously
    record = dict(zip(
        ["timestamp", "src_ip", "src_port", "dst_port", "service",
         "payload", "credentials", "scanner_type", "country", "city"],
        row[:10],
    ))
    async with aiofiles.open(json_path, "a") as f:
        await f.write(json.dumps(record) + "\n")


async def get_recent(db_path: str, limit: int = 100) -> list[dict]:
    sql = """
        SELECT id, timestamp, src_ip, src_port, dst_port, service,
               payload, credentials, scanner_type, country, city
        FROM connections
        ORDER BY id DESC
        LIMIT ?
    """
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, (limit,)) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_stats(db_path: str) -> dict:
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row

        # Total connection count
        async with db.execute("SELECT COUNT(*) AS n FROM connections") as cur:
            total = (await cur.fetchone())["n"]

        # Top 5 services by hit count
        async with db.execute("""
            SELECT service, COUNT(*) AS count
            FROM connections
            GROUP BY service
            ORDER BY count DESC
            LIMIT 5
        """) as cur:
            top_services = [dict(r) for r in await cur.fetchall()]

        # Top 5 source IPs by hit count
        async with db.execute("""
            SELECT src_ip, COUNT(*) AS count
            FROM connections
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 5
        """) as cur:
            top_ips = [dict(r) for r in await cur.fetchall()]

        # Hourly buckets for the last 24 hours - used by the dashboard chart
        async with db.execute("""
            SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour,
                   COUNT(*) AS count
            FROM connections
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour ASC
        """) as cur:
            connections_last_24h = [dict(r) for r in await cur.fetchall()]

        # Scanner type breakdown
        async with db.execute("""
            SELECT COALESCE(scanner_type, 'unknown') AS scanner_type,
                   COUNT(*) AS count
            FROM connections
            GROUP BY scanner_type
            ORDER BY count DESC
        """) as cur:
            scanner_breakdown = [dict(r) for r in await cur.fetchall()]

    return {
        "total_connections": total,
        "top_services": top_services,
        "top_ips": top_ips,
        "connections_last_24h": connections_last_24h,
        "scanner_breakdown": scanner_breakdown,
    }


async def export_json(db_path: str, path: str) -> None:
    # Large limit caps memory usage during full exports rather than streaming unbounded rows
    rows = await get_recent(db_path, limit=10_000_000)
    async with aiofiles.open(path, "w") as f:
        await f.write(json.dumps(rows, indent=2))


async def export_csv(db_path: str, path: str) -> None:
    # Large limit caps memory usage during full exports rather than streaming unbounded rows
    rows = await get_recent(db_path, limit=10_000_000)
    if not rows:
        return
    # Write manually via aiofiles - csv.writer expects a synchronous file object
    async with aiofiles.open(path, "w", newline="") as f:
        await f.write(",".join(rows[0].keys()) + "\n")
        for row in rows:
            await f.write(",".join(str(v) if v is not None else "" for v in row.values()) + "\n")
